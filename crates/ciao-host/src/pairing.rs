use std::collections::{HashMap, VecDeque};

use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::{protocol::base64url, qr::decode_exact};

pub const PAIRING_LIFETIME_SECS: u64 = 5 * 60;
const OUTCOME_RETENTION_SECS: u64 = 10 * 60;
const ATTEMPT_WINDOW_SECS: u64 = 60;
const MAX_ATTEMPTS_PER_WINDOW: usize = 8;
const MAX_TRACKED_RATE_LIMIT_ENDPOINTS: usize = 1_024;

#[derive(Debug, Clone)]
pub struct CreatedOffer {
    pub pairing_id: [u8; 16],
    pub capability: [u8; 32],
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct PairingClaim {
    pub pairing_id: [u8; 16],
    pub capability_hash: [u8; 32],
    pub expires_at: u64,
    token: u64,
}

#[derive(Debug, Clone)]
enum OfferState {
    Pending,
    Validating {
        token: u64,
    },
    Accepted {
        installation_endpoint_id: String,
        connected: bool,
    },
    Expired,
    Rejected {
        message: String,
    },
}

#[derive(Debug, Clone)]
struct Offer {
    capability_hash: [u8; 32],
    created_at: u64,
    expires_at: u64,
    state: OfferState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingStatus {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_endpoint_id: Option<String>,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PairingRejection {
    #[error("unknown pairing offer")]
    UnknownPairing,
    #[error("pairing offer expired")]
    Expired,
    #[error("pairing offer was already consumed")]
    AlreadyConsumed,
    #[error("pairing capability is invalid")]
    InvalidCapability,
    #[error("another pairing proof is being committed")]
    InProgress,
    #[error("pairing validation state changed unexpectedly")]
    Internal,
}

impl PairingRejection {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnknownPairing => "unknown_pairing",
            Self::Expired => "expired",
            Self::AlreadyConsumed => "already_consumed",
            Self::InvalidCapability => "invalid_capability",
            Self::InProgress => "rate_limited",
            Self::Internal => "internal_error",
        }
    }

    pub fn safe_message(self) -> &'static str {
        match self {
            Self::UnknownPairing => "Pairing code is not active. Run ciao pair again.",
            Self::Expired => "Pairing code expired. Run ciao pair again.",
            Self::AlreadyConsumed => "Pairing code was already used. Run ciao pair again.",
            Self::InvalidCapability => "Pairing code was rejected. Run ciao pair again.",
            Self::InProgress => "Too many pairing attempts. Wait and try again.",
            Self::Internal => "Pairing failed internally. Run ciao pair again.",
        }
    }
}

#[derive(Debug, Default)]
pub struct PairingManager {
    offers: HashMap<[u8; 16], Offer>,
    current_pending: Option<[u8; 16]>,
}

impl PairingManager {
    pub fn create(&mut self, now: u64) -> Result<CreatedOffer, PairingRejection> {
        self.cleanup(now);
        if let Some(current) = self.current_pending.take()
            && let Some(offer) = self.offers.get_mut(&current)
        {
            match offer.state {
                OfferState::Pending => {
                    offer.state = OfferState::Rejected {
                        message: "Replaced by a newer pairing code.".into(),
                    };
                }
                OfferState::Validating { .. } => {
                    self.current_pending = Some(current);
                    return Err(PairingRejection::InProgress);
                }
                _ => {}
            }
        }

        let pairing_id = loop {
            let candidate = rand::random::<[u8; 16]>();
            if !self.offers.contains_key(&candidate) {
                break candidate;
            }
        };
        let capability = rand::random::<[u8; 32]>();
        let capability_hash = capability_hash(&capability);
        let expires_at = now.saturating_add(PAIRING_LIFETIME_SECS);
        self.offers.insert(
            pairing_id,
            Offer {
                capability_hash,
                created_at: now,
                expires_at,
                state: OfferState::Pending,
            },
        );
        self.current_pending = Some(pairing_id);
        Ok(CreatedOffer {
            pairing_id,
            capability,
            expires_at,
        })
    }

    pub fn claim(
        &mut self,
        pairing_id: &[u8; 16],
        capability: &[u8; 32],
        now: u64,
    ) -> Result<PairingClaim, PairingRejection> {
        let offer = self
            .offers
            .get_mut(pairing_id)
            .ok_or(PairingRejection::UnknownPairing)?;
        match &offer.state {
            OfferState::Pending => {}
            OfferState::Expired => return Err(PairingRejection::Expired),
            OfferState::Validating { .. } | OfferState::Accepted { .. } => {
                return Err(PairingRejection::AlreadyConsumed);
            }
            OfferState::Rejected { .. } => return Err(PairingRejection::AlreadyConsumed),
        }
        if now >= offer.expires_at {
            offer.state = OfferState::Expired;
            if self.current_pending == Some(*pairing_id) {
                self.current_pending = None;
            }
            return Err(PairingRejection::Expired);
        }
        let submitted_hash = capability_hash(capability);
        if !constant_time_hash_eq(&offer.capability_hash, &submitted_hash) {
            return Err(PairingRejection::InvalidCapability);
        }
        let token = rand::random::<u64>();
        offer.state = OfferState::Validating { token };
        Ok(PairingClaim {
            pairing_id: *pairing_id,
            capability_hash: offer.capability_hash,
            expires_at: offer.expires_at,
            token,
        })
    }

    pub fn complete(
        &mut self,
        claim: &PairingClaim,
        installation_endpoint_id: EndpointId,
        now: u64,
    ) -> Result<(), PairingRejection> {
        let offer = self
            .offers
            .get_mut(&claim.pairing_id)
            .ok_or(PairingRejection::Internal)?;
        if now >= offer.expires_at {
            offer.state = OfferState::Expired;
            self.current_pending = None;
            return Err(PairingRejection::Expired);
        }
        match offer.state {
            OfferState::Validating { token } if token == claim.token => {
                offer.state = OfferState::Accepted {
                    installation_endpoint_id: installation_endpoint_id.to_string(),
                    connected: false,
                };
                if self.current_pending == Some(claim.pairing_id) {
                    self.current_pending = None;
                }
                Ok(())
            }
            _ => Err(PairingRejection::Internal),
        }
    }

    pub fn abort(&mut self, claim: &PairingClaim, now: u64) {
        let Some(offer) = self.offers.get_mut(&claim.pairing_id) else {
            return;
        };
        if !matches!(offer.state, OfferState::Validating { token } if token == claim.token) {
            return;
        }
        if now >= offer.expires_at {
            offer.state = OfferState::Expired;
            self.current_pending = None;
        } else {
            offer.state = OfferState::Pending;
            self.current_pending = Some(claim.pairing_id);
        }
    }

    pub fn mark_connected(&mut self, pairing_id: &[u8; 16], endpoint_id: EndpointId) {
        let Some(offer) = self.offers.get_mut(pairing_id) else {
            return;
        };
        if let OfferState::Accepted {
            installation_endpoint_id,
            connected,
        } = &mut offer.state
            && *installation_endpoint_id == endpoint_id.to_string()
        {
            *connected = true;
        }
    }

    pub fn reject_current(&mut self, message: impl Into<String>) {
        if let Some(current) = self.current_pending.take()
            && let Some(offer) = self.offers.get_mut(&current)
        {
            offer.state = OfferState::Rejected {
                message: message.into(),
            };
        }
    }

    pub fn status(&mut self, encoded_pairing_id: &str, now: u64) -> PairingStatus {
        let Some(pairing_id) = decode_exact::<16>(encoded_pairing_id) else {
            return unknown_status();
        };
        let Some(offer) = self.offers.get_mut(&pairing_id) else {
            return unknown_status();
        };
        if matches!(offer.state, OfferState::Pending) && now >= offer.expires_at {
            offer.state = OfferState::Expired;
            if self.current_pending == Some(pairing_id) {
                self.current_pending = None;
            }
        }
        match &offer.state {
            OfferState::Pending | OfferState::Validating { .. } => PairingStatus {
                state: "pending".into(),
                installation_endpoint_id: None,
                connected: false,
                message: None,
            },
            OfferState::Accepted {
                installation_endpoint_id,
                connected,
            } => PairingStatus {
                state: if *connected { "connected" } else { "accepted" }.into(),
                installation_endpoint_id: Some(installation_endpoint_id.clone()),
                connected: *connected,
                message: None,
            },
            OfferState::Expired => PairingStatus {
                state: "expired".into(),
                installation_endpoint_id: None,
                connected: false,
                message: Some("Pairing code expired. Run ciao pair again.".into()),
            },
            OfferState::Rejected { message } => PairingStatus {
                state: "rejected".into(),
                installation_endpoint_id: None,
                connected: false,
                message: Some(message.clone()),
            },
        }
    }

    fn cleanup(&mut self, now: u64) {
        self.offers.retain(|_, offer| {
            now.saturating_sub(offer.created_at) <= PAIRING_LIFETIME_SECS + OUTCOME_RETENTION_SECS
        });
    }
}

fn unknown_status() -> PairingStatus {
    PairingStatus {
        state: "unknown".into(),
        installation_endpoint_id: None,
        connected: false,
        message: Some("Pairing offer is no longer known. Run ciao pair again.".into()),
    }
}

pub fn capability_hash(capability: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(capability).into()
}

pub fn constant_time_hash_eq(expected: &[u8; 32], submitted: &[u8; 32]) -> bool {
    bool::from(expected.ct_eq(submitted))
}

#[derive(Debug, Default)]
pub struct PairingRateLimiter {
    attempts: HashMap<String, VecDeque<u64>>,
}

impl PairingRateLimiter {
    pub fn check(&mut self, endpoint_id: EndpointId, now: u64) -> Result<(), PairingRejection> {
        for attempts in self.attempts.values_mut() {
            while attempts
                .front()
                .is_some_and(|attempt| now.saturating_sub(*attempt) >= ATTEMPT_WINDOW_SECS)
            {
                attempts.pop_front();
            }
        }
        self.attempts.retain(|_, attempts| !attempts.is_empty());

        let endpoint_id = endpoint_id.to_string();
        if !self.attempts.contains_key(&endpoint_id)
            && self.attempts.len() >= MAX_TRACKED_RATE_LIMIT_ENDPOINTS
        {
            return Err(PairingRejection::InProgress);
        }
        let attempts = self.attempts.entry(endpoint_id).or_default();
        if attempts.len() >= MAX_ATTEMPTS_PER_WINDOW {
            return Err(PairingRejection::InProgress);
        }
        attempts.push_back(now);
        Ok(())
    }
}

pub fn encoded_pairing_id(pairing_id: &[u8; 16]) -> String {
    base64url(pairing_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_validation_is_hashed_constant_time_and_one_use() {
        let mut manager = PairingManager::default();
        let offer = manager.create(100).unwrap();
        let stored = manager.offers.get(&offer.pairing_id).unwrap();
        assert_eq!(stored.capability_hash, capability_hash(&offer.capability));
        assert!(constant_time_hash_eq(
            &stored.capability_hash,
            &capability_hash(&offer.capability)
        ));
        assert!(!constant_time_hash_eq(&stored.capability_hash, &[0; 32]));

        assert!(matches!(
            manager.claim(&offer.pairing_id, &[0; 32], 101),
            Err(PairingRejection::InvalidCapability)
        ));
        let claim = manager
            .claim(&offer.pairing_id, &offer.capability, 101)
            .unwrap();
        let endpoint = iroh::SecretKey::generate().public();
        manager.complete(&claim, endpoint, 102).unwrap();
        assert!(matches!(
            manager.claim(&offer.pairing_id, &offer.capability, 103),
            Err(PairingRejection::AlreadyConsumed)
        ));
    }

    #[test]
    fn expiry_and_failed_persistence_behavior() {
        let mut manager = PairingManager::default();
        let offer = manager.create(100).unwrap();
        assert_eq!(offer.expires_at, 100 + PAIRING_LIFETIME_SECS);
        assert!(matches!(
            manager.claim(&offer.pairing_id, &offer.capability, offer.expires_at),
            Err(PairingRejection::Expired)
        ));

        let offer = manager.create(1_000).unwrap();
        let claim = manager
            .claim(&offer.pairing_id, &offer.capability, 1_001)
            .unwrap();
        manager.abort(&claim, 1_002);
        assert!(
            manager
                .claim(&offer.pairing_id, &offer.capability, 1_003)
                .is_ok()
        );
    }

    #[test]
    fn rate_limiter_is_bounded_and_recovers_after_window() {
        let endpoint = iroh::SecretKey::generate().public();
        let mut limiter = PairingRateLimiter::default();
        for _ in 0..MAX_ATTEMPTS_PER_WINDOW {
            assert!(limiter.check(endpoint, 100).is_ok());
        }
        assert!(matches!(
            limiter.check(endpoint, 100),
            Err(PairingRejection::InProgress)
        ));
        assert!(limiter.check(endpoint, 100 + ATTEMPT_WINDOW_SECS).is_ok());
    }

    #[test]
    fn rate_limiter_bounds_tracked_endpoint_memory() {
        let mut limiter = PairingRateLimiter::default();
        for _ in 0..MAX_TRACKED_RATE_LIMIT_ENDPOINTS {
            assert!(
                limiter
                    .check(iroh::SecretKey::generate().public(), 100)
                    .is_ok()
            );
        }
        assert!(matches!(
            limiter.check(iroh::SecretKey::generate().public(), 100),
            Err(PairingRejection::InProgress)
        ));
        assert!(
            limiter
                .check(
                    iroh::SecretKey::generate().public(),
                    100 + ATTEMPT_WINDOW_SECS
                )
                .is_ok()
        );
    }

    #[test]
    fn a_new_offer_rejects_the_old_pending_offer() {
        let mut manager = PairingManager::default();
        let old = manager.create(100).unwrap();
        let _new = manager.create(101).unwrap();
        let status = manager.status(&encoded_pairing_id(&old.pairing_id), 102);
        assert_eq!(status.state, "rejected");
        assert!(status.message.unwrap().contains("newer"));
    }
}
