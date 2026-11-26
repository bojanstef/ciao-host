//! The one terminal input queue. Spec 002 §8: queues are byte-bounded, and a full input queue
//! stops QUIC reads instead of failing the terminal. Every backend drains the same type, so
//! a burst of small frames (one per key or scrolled line) waits for room instead of failing.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::{
    host_protocol::{HOST_PENDING_INPUT_BYTES, MAX_DATA_PAYLOAD},
    pty::PtyError,
};

/// Queued input bytes. They hold their share of the byte bound until the backend drops them.
pub(crate) struct InputChunk {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

impl InputChunk {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Room for one frame in the byte bound, obtained before the frame is queued.
pub(crate) struct InputPermit(OwnedSemaphorePermit);

pub(crate) struct InputQueue {
    sender: Option<mpsc::Sender<InputChunk>>,
    bytes: Arc<Semaphore>,
    high_water: AtomicUsize,
}

impl InputQueue {
    pub(crate) fn new() -> (Self, mpsc::Receiver<InputChunk>) {
        // Every chunk holds at least one byte of the bound, so the byte bound is the only limit
        // that can ever be reached and `push` never finds the channel full.
        let (sender, receiver) = mpsc::channel(HOST_PENDING_INPUT_BYTES);
        let queue = Self {
            sender: Some(sender),
            bytes: Arc::new(Semaphore::new(HOST_PENDING_INPUT_BYTES)),
            high_water: AtomicUsize::new(0),
        };
        (queue, receiver)
    }

    /// Waits for room for `len` bytes. The future owns nothing borrowed from the queue, so a
    /// caller can keep draining terminal output while it waits.
    pub(crate) fn reserve(
        &self,
        len: usize,
    ) -> impl Future<Output = Result<InputPermit, PtyError>> + Send + 'static {
        let bytes = self.bytes.clone();
        let count = (1..=MAX_DATA_PAYLOAD)
            .contains(&len)
            .then(|| u32::try_from(len).ok())
            .flatten();
        async move {
            let count = count.ok_or(PtyError::InvalidInput)?;
            bytes
                .acquire_many_owned(count)
                .await
                .map(InputPermit)
                .map_err(|_| PtyError::InputClosed)
        }
    }

    /// Queues `bytes` in the room `permit` reserved for them.
    pub(crate) fn push(&self, bytes: Vec<u8>, permit: InputPermit) -> Result<(), PtyError> {
        if permit.0.num_permits() != bytes.len() {
            return Err(PtyError::InvalidInput);
        }
        let sender = self.sender.as_ref().ok_or(PtyError::InputClosed)?;
        self.high_water.fetch_max(
            HOST_PENDING_INPUT_BYTES - self.bytes.available_permits(),
            Ordering::Relaxed,
        );
        sender
            .try_send(InputChunk {
                bytes,
                _permit: permit.0,
            })
            .map_err(|_| PtyError::InputClosed)
    }

    #[cfg(test)]
    pub(crate) async fn send(&self, bytes: Vec<u8>) -> Result<(), PtyError> {
        let permit = self.reserve(bytes.len()).await?;
        self.push(bytes, permit)
    }

    /// Stops accepting input. Queued chunks still reach the backend; waiting senders fail.
    pub(crate) fn close(&mut self) {
        self.sender.take();
        self.bytes.close();
    }

    pub(crate) fn high_water(&self) -> usize {
        self.high_water.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn small_frames_are_bounded_by_bytes_not_by_count() {
        let (queue, _backend) = InputQueue::new();
        for _ in 0..HOST_PENDING_INPUT_BYTES / 3 {
            queue.send(b"\x1b[A".to_vec()).await.unwrap();
        }
        assert_eq!(queue.high_water(), HOST_PENDING_INPUT_BYTES / 3 * 3);
        // The bound is reached: the next frame waits for room rather than failing.
        let mut next = std::pin::pin!(queue.send(b"\x1b[A".to_vec()));
        assert!(futures_util::poll!(next.as_mut()).is_pending());
    }

    #[tokio::test]
    async fn room_returns_when_the_backend_takes_a_chunk() {
        let (queue, mut backend) = InputQueue::new();
        queue
            .send(vec![b'x'; MAX_DATA_PAYLOAD])
            .await
            .expect("first frame");
        for _ in 1..HOST_PENDING_INPUT_BYTES / MAX_DATA_PAYLOAD {
            queue.send(vec![b'x'; MAX_DATA_PAYLOAD]).await.unwrap();
        }
        let waiting = queue.reserve(1);
        drop(backend.recv().await);
        let permit = waiting
            .await
            .expect("room after the backend drained a chunk");
        queue.push(b"y".to_vec(), permit).unwrap();
    }

    #[tokio::test]
    async fn closed_backend_or_queue_reports_input_closed() {
        let (mut queue, backend) = InputQueue::new();
        drop(backend);
        assert_eq!(queue.send(b"a".to_vec()).await, Err(PtyError::InputClosed));
        let waiting = queue.reserve(1);
        queue.close();
        assert_eq!(waiting.await.err(), Some(PtyError::InputClosed));
    }

    #[tokio::test]
    async fn invalid_frames_are_rejected_before_waiting() {
        let (queue, _backend) = InputQueue::new();
        assert_eq!(queue.send(Vec::new()).await, Err(PtyError::InvalidInput));
        assert_eq!(
            queue.send(vec![0; MAX_DATA_PAYLOAD + 1]).await,
            Err(PtyError::InvalidInput)
        );
        let permit = queue.reserve(2).await.unwrap();
        assert_eq!(
            queue.push(b"a".to_vec(), permit),
            Err(PtyError::InvalidInput)
        );
    }
}
