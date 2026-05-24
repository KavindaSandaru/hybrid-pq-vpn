use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, DecapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use x25519_dalek::{PublicKey, StaticSecret};

const DEFAULT_REPLAY_WINDOW: usize = 4096;

pub struct HybridHandshake;

#[derive(Debug, Clone)]
pub struct ReplayGuard {
    seen: HashSet<[u8; 12]>,
    order: VecDeque<[u8; 12]>,
    max_entries: usize,
}

impl ReplayGuard {
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            max_entries: max_entries.max(1),
        }
    }

    pub fn is_fresh_packet(&mut self, data: &[u8]) -> bool {
        if data.len() < 12 {
            return false;
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[..12]);
        if self.seen.contains(&nonce) {
            return false;
        }

        self.seen.insert(nonce);
        self.order.push_back(nonce);
        while self.order.len() > self.max_entries {
            if let Some(expired) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }

        true
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW)
    }
}

impl HybridHandshake {
    pub fn generate_x25519_keys() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    pub fn generate_pq_keys() -> (DecapsulationKey<MlKem768Params>, Vec<u8>) {
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        (dk, ek.as_bytes().to_vec())
    }

    pub fn decapsulate_pq_key(
        dk: &DecapsulationKey<MlKem768Params>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let ct_array: &[u8; 1088] = ciphertext
            .try_into()
            .map_err(|_| "Invalid ciphertext length")?;
        let shared_secret = dk
            .decapsulate(ct_array.into())
            .map_err(|_| "Decapsulation failed")?;
        let ss_bytes: &[u8] = shared_secret.as_ref();
        Ok(ss_bytes.to_vec())
    }

    pub fn derive_session_key(x_shared: &[u8], pq_shared: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(x_shared);
        hasher.update(pq_shared);
        let combined = hasher.finalize();

        let hk = Hkdf::<Sha256>::new(None, &combined);
        let mut okm = [0u8; 32];
        hk.expand(b"ntz-proto-hybrid-v1", &mut okm)
            .expect("HKDF expansion failed");
        okm
    }

    pub fn encrypt_data(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("encryption failure");
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        result
    }

    pub fn decrypt_data(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 12 {
            return None;
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(&data[..12]);
        cipher.decrypt(nonce, &data[12..]).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_guard_accepts_new_nonces_and_rejects_replays() {
        let mut guard = ReplayGuard::new(8);
        let packet = [7u8; 32];

        assert!(guard.is_fresh_packet(&packet));
        assert!(!guard.is_fresh_packet(&packet));
    }

    #[test]
    fn replay_guard_eviction_allows_old_nonce_after_window() {
        let mut guard = ReplayGuard::new(2);
        let first = [1u8; 32];
        let second = [2u8; 32];
        let third = [3u8; 32];

        assert!(guard.is_fresh_packet(&first));
        assert!(guard.is_fresh_packet(&second));
        assert!(guard.is_fresh_packet(&third));
        assert!(guard.is_fresh_packet(&first));
    }
}
