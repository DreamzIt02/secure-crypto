// ## 1. `src/recovery/checkpoint.rs`

// Purpose: capture digest state + metadata for resumption.

//! recovery/checkpoint.rs
//! Defines checkpoint structures for resumable hashing and decryption.
use std::any::Any;
// trait from RustCrypto digest 0.11 (Standard in 2026)
use digest::{array::Array, crypto_common::hazmat::SerializableState}; 
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use blake3::{Hasher as Blake3Hasher};
use crate::crypto::{DigestError, digest::{DigestAlg, DigestState}};

pub trait Checkpointable: Send + Sync {
    fn export(&self) -> Vec<u8>;
    fn segment_index(&self) -> u32;
    fn summary(&self) -> String;
    fn as_any(&self) -> &dyn Any; 
}

#[derive(Debug, Clone)]
pub enum SerializedState {
    Sha256(Array<u8, <Sha256 as SerializableState>::SerializedStateSize>),
    Sha512(Array<u8, <Sha512 as SerializableState>::SerializedStateSize>),
    Sha3_256(Array<u8, <Sha3_256 as SerializableState>::SerializedStateSize>),
    Sha3_512(Array<u8, <Sha3_512 as SerializableState>::SerializedStateSize>),
    /// Blake3 is now marked as NoState because it does not support resume in 1.8.3
    Blake3NoState, 
}

impl SerializedState {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SerializedState::Sha256(arr) => arr.to_vec(),
            SerializedState::Sha512(arr) => arr.to_vec(),
            SerializedState::Sha3_256(arr) => arr.to_vec(),
            SerializedState::Sha3_512(arr) => arr.to_vec(),
            SerializedState::Blake3NoState => Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegmentCheckpoint {
    pub alg: DigestAlg,
    pub segment_index: u32,
    pub next_frame_index: u32,
    pub state: SerializedState, 
}

impl SegmentCheckpoint {
    pub fn from_state(alg: DigestAlg, segment_index: u32, next_frame_index: u32, state: &DigestState) -> Self {
        let state = match state {
            DigestState::Sha256(h)   => SerializedState::Sha256(h.serialize()),
            DigestState::Sha512(h)   => SerializedState::Sha512(h.serialize()),
            DigestState::Sha3_256(h) => SerializedState::Sha3_256(h.serialize()),
            DigestState::Sha3_512(h) => SerializedState::Sha3_512(h.serialize()),
            // This effectively "drops" resume support by restarting the hash for this alg.
            DigestState::Blake3(_)   => SerializedState::Blake3NoState, 
        };
        Self { alg, segment_index, next_frame_index, state }
    }
    pub fn resume_from_checkpoint(self) -> Result<DigestState, DigestError> {
        match (self.alg, self.state) {
            (DigestAlg::Sha256, SerializedState::Sha256(arr)) => Sha256::deserialize(&arr).map(DigestState::Sha256).map_err(|_| DigestError::InvalidFormat),
            (DigestAlg::Sha512, SerializedState::Sha512(arr)) => Sha512::deserialize(&arr).map(DigestState::Sha512).map_err(|_| DigestError::InvalidFormat),
            (DigestAlg::Sha3_256, SerializedState::Sha3_256(arr)) => Sha3_256::deserialize(&arr).map(DigestState::Sha3_256).map_err(|_| DigestError::InvalidFormat),
            (DigestAlg::Sha3_512, SerializedState::Sha3_512(arr)) => Sha3_512::deserialize(&arr).map(DigestState::Sha3_512).map_err(|_| DigestError::InvalidFormat),
            // Blake3 Refactor: Instead of an error, we return a fresh Hasher.
            // This effectively "drops" resume support by restarting the hash for this alg.
            (DigestAlg::Blake3, _) => Ok(DigestState::Blake3(Blake3Hasher::new())),
            _ => Err(DigestError::InvalidFormat),
        }
    }

}

impl Checkpointable for SegmentCheckpoint {
    fn export(&self) -> Vec<u8> { self.state.to_bytes() }
    fn segment_index(&self) -> u32 { self.segment_index }
    fn summary(&self) -> String { format!("SegmentCheckpoint: alg={:?}, segment={}, next={}", self.alg, self.segment_index, self.next_frame_index) }
    fn as_any(&self) -> &dyn Any { self }
}

// DecryptState remains unchanged as it typically relies on simple counters (CTR/ChaCha)
// which are natively resumable by just storing the counter [u8] or [u32].
#[derive(Debug, Clone)]
pub enum DecryptState {
    AesCtr([u8; 16]),
    ChaCha20([u8; 32]),
}

impl DecryptState {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DecryptState::AesCtr(arr) => arr.to_vec(),
            DecryptState::ChaCha20(arr) => arr.to_vec(),
        }
    }
    pub fn from_bytes(alg_type: &str, bytes: &[u8]) -> Option<Self> {
        match alg_type {
            "AesCtr" if bytes.len() == 16 => Some(DecryptState::AesCtr(bytes.try_into().ok()?)),
            "ChaCha20" if bytes.len() == 32 => Some(DecryptState::ChaCha20(bytes.try_into().ok()?)),
            _ => None,
        }
    }
}

pub struct DecryptCheckpoint {
    pub segment_index: u32,
    pub frame_index: u32,
    pub state: DecryptState,
}

impl Checkpointable for DecryptCheckpoint {
    fn export(&self) -> Vec<u8> { self.state.to_bytes() }
    fn segment_index(&self) -> u32 { self.segment_index }
    fn summary(&self) -> String { format!("DecryptCheckpoint: segment={}, frame={}", self.segment_index, self.frame_index) }
    fn as_any(&self) -> &dyn Any { self }
}
