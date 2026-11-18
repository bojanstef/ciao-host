//! Streaming platform SHA-256, avoiding build-profile-dependent software hashing of 512 MiB.
//! CommonDigest.h: CC_LONG is uint32_t and CC_SHA256_CTX is count[2], hash[8], wbuf[16].
#[repr(C)]
#[derive(Default)]
struct Context {
    count: [u32; 2],
    hash: [u32; 8],
    buffer: [u32; 16],
}
const _: () =
    assert!(std::mem::size_of::<Context>() == 104 && std::mem::align_of::<Context>() == 4);
#[link(name = "System")]
unsafe extern "C" {
    fn CC_SHA256_Init(context: *mut Context) -> i32;
    fn CC_SHA256_Update(context: *mut Context, bytes: *const std::ffi::c_void, len: u32) -> i32;
    fn CC_SHA256_Final(output: *mut u8, context: *mut Context) -> i32;
}
pub(super) struct Sha256(Context);
impl Sha256 {
    pub(super) fn new() -> Option<Self> {
        let mut context = Context::default();
        // SAFETY: correctly sized/aligned owned context; CommonCrypto retains no pointer.
        (unsafe { CC_SHA256_Init(&mut context) } == 1).then_some(Self(context))
    }
    pub(super) fn update(&mut self, bytes: &[u8]) -> Option<()> {
        let size = u32::try_from(bytes.len()).ok()?;
        // SAFETY: initialized context and live readable slice of the checked length.
        (unsafe { CC_SHA256_Update(&mut self.0, bytes.as_ptr().cast(), size) } == 1).then_some(())
    }
    pub(super) fn finish(mut self) -> Option<String> {
        let mut output = [0u8; 32];
        // SAFETY: initialized context, exact SHA-256 output buffer, neither pointer escapes.
        if unsafe { CC_SHA256_Final(output.as_mut_ptr(), &mut self.0) } != 1 {
            return None;
        }
        Some(output.iter().map(|b| format!("{b:02x}")).collect())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn platform_digest_matches_known_vectors_and_chunking() {
        assert_eq!(
            Sha256::new().unwrap().finish().unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut digest = Sha256::new().unwrap();
        for b in b"abc" {
            digest.update(&[*b]).unwrap();
        }
        assert_eq!(
            digest.finish().unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
