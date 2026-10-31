// Copyright 2022 labring. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared-secret authentication for the RPC control plane.
//!
//! The client sends a single fixed-size handshake frame as the first bytes on
//! a connection:
//!
//! ```text
//! | magic "SFL1" | version u32 | timestamp u64 | nonce [u8; 16] | hmac [u8; 32] |
//! | 4 bytes      | 4 bytes     | 8 bytes       | 16 bytes       | 32 bytes      |
//! ```
//!
//! The HMAC-SHA256 covers the first 32 bytes of the frame. Timestamps are
//! accepted within +-60 seconds and nonces are cached for 120 seconds to
//! detect replays.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const AUTH_MAGIC: &[u8; 4] = b"SFL1";
pub const AUTH_VERSION: u32 = 1;
pub const AUTH_FRAME_SIZE: usize = 4 + 4 + 8 + 16 + 32;
pub const AUTH_TIMESTAMP_WINDOW_SECS: u64 = 60;
pub const AUTH_NONCE_RETENTION_SECS: u64 = 120;
pub const AUTH_NONCE_CACHE_LIMIT: usize = 65536;
pub const AUTH_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
pub const AUTH_TOKEN_ENV: &str = "SEALFS_RPC_TOKEN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    BadMagic,
    BadVersion,
    StaleTimestamp,
    BadHmac,
    ReplayedNonce,
    NonceCacheFull,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::BadMagic => write!(f, "bad handshake magic"),
            AuthError::BadVersion => write!(f, "unsupported handshake version"),
            AuthError::StaleTimestamp => write!(f, "handshake timestamp outside allowed window"),
            AuthError::BadHmac => write!(f, "handshake HMAC verification failed"),
            AuthError::ReplayedNonce => write!(f, "handshake nonce has already been used"),
            AuthError::NonceCacheFull => write!(f, "handshake nonce cache is full"),
        }
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the shared secret from the environment. Returns `None` when the
/// variable is unset or empty, in which case the caller must stay on loopback
/// and reject management operations.
pub fn token_from_env() -> Option<Vec<u8>> {
    match std::env::var(AUTH_TOKEN_ENV) {
        Ok(value) if !value.is_empty() => Some(value.into_bytes()),
        _ => None,
    }
}

pub fn is_loopback_address(address: &str) -> bool {
    if address == "::1" || address == "localhost" {
        return true;
    }
    let host = if let Some(rest) = address.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else if let Some((host, port)) = address.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            host
        } else {
            address
        }
    } else {
        address
    };
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

pub fn build_auth_frame(secret: &[u8], timestamp: u64, nonce: &[u8; 16]) -> [u8; AUTH_FRAME_SIZE] {
    let mut frame = [0u8; AUTH_FRAME_SIZE];
    frame[0..4].copy_from_slice(AUTH_MAGIC);
    frame[4..8].copy_from_slice(&AUTH_VERSION.to_le_bytes());
    frame[8..16].copy_from_slice(&timestamp.to_le_bytes());
    frame[16..32].copy_from_slice(nonce);
    let mac = hmac_sha256(secret, &frame[0..32]);
    frame[32..64].copy_from_slice(&mac);
    frame
}

#[derive(Default)]
pub struct ReplayCache {
    seen: HashMap<[u8; 16], u64>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    fn prune(&mut self, now: u64) {
        self.seen
            .retain(|_, seen_at| now.saturating_sub(*seen_at) <= AUTH_NONCE_RETENTION_SECS);
    }

    /// Returns true if the nonce was not seen before. Must only be called
    /// after the frame HMAC has been verified, otherwise unauthenticated peers
    /// could fill the cache.
    pub fn check_and_insert(&mut self, nonce: [u8; 16], now: u64) -> bool {
        self.prune(now);
        if self.seen.contains_key(&nonce) {
            return false;
        }
        if self.seen.len() >= AUTH_NONCE_CACHE_LIMIT {
            return false;
        }
        self.seen.insert(nonce, now);
        true
    }
}

pub struct AuthState {
    secret: Vec<u8>,
    replay: std::sync::Mutex<ReplayCache>,
}

impl AuthState {
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret,
            replay: std::sync::Mutex::new(ReplayCache::new()),
        }
    }

    pub fn from_env() -> Option<Self> {
        token_from_env().map(AuthState::new)
    }

    pub fn verify_frame(&self, frame: &[u8]) -> Result<(), AuthError> {
        self.verify_frame_at(frame, unix_now())
    }

    pub fn verify_frame_at(&self, frame: &[u8], now: u64) -> Result<(), AuthError> {
        if frame.len() != AUTH_FRAME_SIZE {
            return Err(AuthError::BadMagic);
        }
        if &frame[0..4] != AUTH_MAGIC.as_slice() {
            return Err(AuthError::BadMagic);
        }
        let version = u32::from_le_bytes(frame[4..8].try_into().unwrap());
        if version != AUTH_VERSION {
            return Err(AuthError::BadVersion);
        }
        let timestamp = u64::from_le_bytes(frame[8..16].try_into().unwrap());
        if now.abs_diff(timestamp) > AUTH_TIMESTAMP_WINDOW_SECS {
            return Err(AuthError::StaleTimestamp);
        }
        let expected = hmac_sha256(&self.secret, &frame[0..32]);
        if !constant_time_eq(&expected, &frame[32..64]) {
            return Err(AuthError::BadHmac);
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&frame[16..32]);
        let mut replay = match self.replay.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if replay.check_and_insert(nonce, now) {
            Ok(())
        } else {
            Err(AuthError::ReplayedNonce)
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend(block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK_SIZE + 32);
    outer.extend(block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut message = Vec::with_capacity(data.len() + 72);
    message.extend_from_slice(data);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_be_bytes());

    for chunk in message.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn frame_with(secret: &[u8], timestamp: u64, nonce: [u8; 16]) -> [u8; AUTH_FRAME_SIZE] {
        build_auth_frame(secret, timestamp, &nonce)
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_matches_rfc4231_case_1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn accepts_valid_frame() {
        let state = AuthState::new(b"secret".to_vec());
        let now = 1_700_000_000;
        let frame = frame_with(b"secret", now, [7u8; 16]);
        assert_eq!(state.verify_frame_at(&frame, now), Ok(()));
    }

    #[test]
    fn rejects_wrong_hmac() {
        let state = AuthState::new(b"secret".to_vec());
        let now = 1_700_000_000;
        let frame = frame_with(b"other-secret", now, [1u8; 16]);
        assert_eq!(state.verify_frame_at(&frame, now), Err(AuthError::BadHmac));
    }

    #[test]
    fn rejects_stale_and_future_timestamps() {
        let state = AuthState::new(b"secret".to_vec());
        let now = 1_700_000_000;
        let stale = frame_with(b"secret", now - AUTH_TIMESTAMP_WINDOW_SECS - 1, [2u8; 16]);
        assert_eq!(
            state.verify_frame_at(&stale, now),
            Err(AuthError::StaleTimestamp)
        );
        let future = frame_with(b"secret", now + AUTH_TIMESTAMP_WINDOW_SECS + 1, [3u8; 16]);
        assert_eq!(
            state.verify_frame_at(&future, now),
            Err(AuthError::StaleTimestamp)
        );
    }

    #[test]
    fn rejects_replayed_nonce() {
        let state = AuthState::new(b"secret".to_vec());
        let now = 1_700_000_000;
        let frame = frame_with(b"secret", now, [4u8; 16]);
        assert_eq!(state.verify_frame_at(&frame, now), Ok(()));
        assert_eq!(
            state.verify_frame_at(&frame, now),
            Err(AuthError::ReplayedNonce)
        );
    }

    #[test]
    fn rejects_bad_magic_and_version() {
        let state = AuthState::new(b"secret".to_vec());
        let now = 1_700_000_000;
        let mut frame = frame_with(b"secret", now, [5u8; 16]);
        frame[0] = b'X';
        assert_eq!(state.verify_frame_at(&frame, now), Err(AuthError::BadMagic));

        let mut frame = frame_with(b"secret", now, [6u8; 16]);
        frame[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            state.verify_frame_at(&frame, now),
            Err(AuthError::BadVersion)
        );
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_address("127.0.0.1:8081"));
        assert!(is_loopback_address("127.1.2.3:1"));
        assert!(is_loopback_address("localhost:8081"));
        assert!(is_loopback_address("[::1]:8081"));
        assert!(is_loopback_address("::1"));
        assert!(!is_loopback_address("0.0.0.0:8081"));
        assert!(!is_loopback_address("10.0.0.1:8081"));
        assert!(!is_loopback_address("[::]:8081"));
    }
}
