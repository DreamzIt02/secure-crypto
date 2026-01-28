use std::fmt;
use std::convert::TryFrom;
use num_enum::TryFromPrimitive;

use sha2::{Digest as _, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use blake3;

use crate::utils::enum_name_or_hex;

/// Digest-related errors.
#[derive(Debug)]
pub enum DigestError {
    UnknownAlgorithm { raw: u16 },
    DigestMismatch,
    InvalidFormat,
    InvalidLength { have: usize, need: usize },
}
impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DigestError::*;
        match self {
            UnknownAlgorithm { raw } =>
                write!(f, "unknown algorithm: {}",
                    enum_name_or_hex::<DigestAlg>(*raw)),
            DigestMismatch => write!(f, "invalid header: {}", "Invalid frame header"),
            InvalidFormat => write!(f, "invalid header: {}", "Invalid frame header"),
            InvalidLength { have, need } =>
                write!(f, "digest buffer too short: {} < {}", have, need),
        }
    }
}
/// Supported digest algorithms (extensible).
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum DigestAlg {
    // Sha224   = 0x0001,
    Sha256   = 0x0002,
    // Sha384   = 0x0003,
    Sha512   = 0x0004,
    // Sha3_224 = 0x0101,
    Sha3_256 = 0x0102,
    // Sha3_384 = 0x0103,
    Sha3_512 = 0x0104,
    Blake3   = 0x0201, // UN-KEYED Blake3
}
impl DigestAlg {
    pub fn can_resume(&self) -> bool {
        let state = match self {
            DigestAlg::Blake3       => false,
            _       => true,
        };
        state
    }
}

// impl TryFrom<u16> for DigestAlg {
//     type Error = DigestError;

//     fn try_from(value: u16) -> Result<Self, Self::Error> {
//         match value {
//             // 0x0001 => Ok(DigestAlg::Sha224),
//             0x0002 => Ok(DigestAlg::Sha256),
//             // 0x0003 => Ok(DigestAlg::Sha384),
//             0x0004 => Ok(DigestAlg::Sha512),
//             // 0x0101 => Ok(DigestAlg::Sha3_224),
//             0x0102 => Ok(DigestAlg::Sha3_256),
//             // 0x0103 => Ok(DigestAlg::Sha3_384),
//             0x0104 => Ok(DigestAlg::Sha3_512),
//             0x0201 => Ok(DigestAlg::Blake3),
//             _ => Err(DigestError::UnknownAlgorithm(value)),
//         }
//     }
// }

impl fmt::Display for DigestAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            DigestAlg::Sha256       => "Sha256",
            DigestAlg::Sha512       => "Sha512",
            DigestAlg::Sha3_256       => "Sha3_256",
            DigestAlg::Sha3_512       => "Sha3_512",
            DigestAlg::Blake3       => "Blake3",
        };
        f.write_str(name)
    }
}

/// Internal hashing state.
#[derive(Debug, Clone)]
pub enum DigestState {
    // Sha224(Sha224),
    Sha256(Sha256),
    // Sha384(Sha384),
    Sha512(Sha512),
    // Sha3_224(Sha3_224),
    Sha3_256(Sha3_256),
    // Sha3_384(Sha3_384),
    Sha3_512(Sha3_512),
    Blake3(blake3::Hasher),
}

impl DigestState {
    /// Create a new digest state.
    #[inline]
    pub fn new(alg: DigestAlg) -> Self {
        match alg {
            DigestAlg::Sha256   => DigestState::Sha256(Sha256::new()),
            DigestAlg::Sha512   => DigestState::Sha512(Sha512::new()),
            DigestAlg::Sha3_256 => DigestState::Sha3_256(Sha3_256::new()),
            DigestAlg::Sha3_512 => DigestState::Sha3_512(Sha3_512::new()),
            DigestAlg::Blake3   => DigestState::Blake3(blake3::Hasher::new()),
        }
    }

    /// Helper to get the algorithm type from an existing state
    pub fn alg(&self) -> DigestAlg {
        match self {
            DigestState::Sha256(_)   => DigestAlg::Sha256,
            DigestState::Sha512(_)   => DigestAlg::Sha512,
            DigestState::Sha3_256(_) => DigestAlg::Sha3_256,
            DigestState::Sha3_512(_) => DigestAlg::Sha3_512,
            DigestState::Blake3(_)   => DigestAlg::Blake3,
        }
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        match self {
            // DigestState::Sha224(h)   => h.update(data),
            DigestState::Sha256(h)   => h.update(data),
            // DigestState::Sha384(h)   => h.update(data),
            DigestState::Sha512(h)   => h.update(data),
            // DigestState::Sha3_224(h) => h.update(data),
            DigestState::Sha3_256(h) => h.update(data),
            // DigestState::Sha3_384(h) => h.update(data),
            DigestState::Sha3_512(h) => h.update(data),
            DigestState::Blake3(h)   => { h.update(data); },
        }
    }

    #[inline]
    fn finalize(self) -> Vec<u8> {
        match self {
            // DigestState::Sha224(h)   => h.finalize().to_vec(),
            DigestState::Sha256(h)   => h.finalize().to_vec(),
            // DigestState::Sha384(h)   => h.finalize().to_vec(),
            DigestState::Sha512(h)   => h.finalize().to_vec(),
            // DigestState::Sha3_224(h) => h.finalize().to_vec(),
            DigestState::Sha3_256(h) => h.finalize().to_vec(),
            // DigestState::Sha3_384(h) => h.finalize().to_vec(),
            DigestState::Sha3_512(h) => h.finalize().to_vec(),
            DigestState::Blake3(h)   => h.finalize().as_bytes().to_vec(),
        }
    }
}

/// Digest frame decoded from plaintext.
#[derive(Debug)]
pub struct DigestFrame {
    pub algorithm: DigestAlg,
    pub digest: Vec<u8>,
}


/// [ alg_id: u16 BE ][ digest_len: u16 BE ][ digest bytes ]
impl DigestFrame {
    #[inline]
    pub fn new(alg: DigestAlg, digest: Vec<u8>) -> Self {
        Self {
            algorithm: alg,
            digest
        }
    }
    /// Encode into wire format (plaintext):
    /// [ alg_id: u16 BE ][ digest_len: u16 BE ][ digest bytes ]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.digest.len());

        // algorithm ID
        let alg_id: u16 = self.algorithm as u16;
        out.extend_from_slice(&alg_id.to_be_bytes());

        // digest length
        let len: u16 = self.digest.len() as u16;
        out.extend_from_slice(&len.to_be_bytes());

        // digest bytes
        out.extend_from_slice(&self.digest);

        out
    }
    /// Wire format (plaintext):
    /// [ alg_id: u16 BE ][ digest_len: u16 BE ][ digest bytes ]
    pub fn decode(plaintext: &[u8]) -> Result<Self, DigestError> {
        if plaintext.len() < 4 {
            return Err(DigestError::InvalidFormat);
        }

        let alg_id = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        let algorithm = match DigestAlg::try_from(alg_id) {
            Ok(r) => r,
            Err(_) => {
                return Err(DigestError::UnknownAlgorithm { raw: alg_id })
            }
        };

        let length = u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize;
        let actual = plaintext.len() - 4;

        if length != actual {
            return Err(DigestError::InvalidLength {
                need: length,
                have: actual,
            });
        }

        Ok(Self {
            algorithm,
            digest: plaintext[4..].to_vec(),
        })
    }
}

// ✔ extensible
// ✔ version-safe
// ✔ consistent with headers

/// Incremental segment digest builder.
///
/// This builder hashes **canonical digest input bytes**,
/// not plaintext and not wire bytes.
///
/// Digest input format (canonical):
///
/// ```text
/// segment_index   (u32 LE)
/// frame_count     (u32 LE)
/// for each DATA frame, ordered by frame_index:
///   frame_index   (u32 LE)
///   ciphertext_len(u32 LE)
///   ciphertext    (N bytes)
/// ```
pub struct SegmentDigestBuilder {
    pub alg: DigestAlg,
    pub state: DigestState,
    pub segment_index: u32,
    pub frame_count: u32,
    pub finalized: bool,
}
impl SegmentDigestBuilder {
    /// Create a new digest builder.
    #[inline]
    pub fn new(alg: DigestAlg, segment_index: u32, frame_count: u32) -> Self {
        let mut state = DigestState::new(alg);

        // Feed segment header: MUST be done for a fresh segment
        state.update(&segment_index.to_le_bytes());
        state.update(&frame_count.to_le_bytes());

        Self {
            alg,
            state,
            segment_index,
            frame_count,
            finalized: false,
        }
    }

    /// Create a verifier by resuming from an existing hydrated state.
    /// Used for frame-level resume within a single segment.
    pub fn with_state(
        state: DigestState,
        segment_index: u32,
        frame_count: u32,
    ) -> Self {
        // FIX: Extract the algorithm from the existing state
        let alg = state.alg();

        // FIX: We do NOT update the state with segment_index/frame_count here.
        // If we are resuming, those bytes were already hashed before the 
        // state was checkpointed. Re-hashing them would cause a digest mismatch.

        Self {
            alg,
            state,
            segment_index,
            frame_count,
            finalized: false,
        }
    }
    /// Returns a clone of the current internal state for checkpointing.
    pub fn state(&self) -> DigestState {
        self.state.clone() // DigestState must implement Clone
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        debug_assert!(!self.finalized);
        self.state.update(data);
    }

    /// Feed one DATA frame (strictly ascending `frame_index`).
    #[inline]
    pub fn update_frame(&mut self, frame_index: u32, ciphertext: &[u8]) {
        self.update(&frame_index.to_le_bytes());
        self.update(&(ciphertext.len() as u32).to_le_bytes());
        self.update(ciphertext);
        println!("builder input: seg={} frame_count={} frame_index={} ct_len={}",
            self.segment_index, self.frame_count, frame_index, ciphertext.len());
    }

    /// Finalize and return digest bytes.
    ///
    /// Can be called only once.
    #[inline]
    pub fn finalize(mut self) -> Vec<u8> {
        self.finalized = true;
        self.state.finalize()
    }

}

/// Streaming verifier (bit-exact with `DigestBuilder`).
pub struct SegmentDigestVerifier {
    _alg: DigestAlg,
    state: DigestState,
    expected: Vec<u8>,
    segment_index: u32,
    frame_count: u32,
    finalized: bool,
}

impl SegmentDigestVerifier {
    /// Create a fresh verifier for a new segment.
    /// This hashes the segment header (index and frame count) immediately.
    pub fn new(
        alg: DigestAlg,
        segment_index: u32,
        frame_count: u32,
        expected: Vec<u8>,
    ) -> Self {
        let mut state = DigestState::new(alg);

        // Feed segment header: MUST be done for a fresh segment
        state.update(&segment_index.to_le_bytes());
        state.update(&frame_count.to_le_bytes());

        Self {
            _alg: alg,
            state,
            expected,
            segment_index,
            frame_count,
            finalized: false,
        }
    }

    /// Create a verifier by resuming from an existing hydrated state.
    /// Used for frame-level resume within a single segment.
    pub fn with_state(
        state: DigestState,
        segment_index: u32,
        frame_count: u32,
        expected: Vec<u8>,
    ) -> Self {
        // FIX: Extract the algorithm from the existing state
        let alg = state.alg();

        // FIX: We do NOT update the state with segment_index/frame_count here.
        // If we are resuming, those bytes were already hashed before the 
        // state was checkpointed. Re-hashing them would cause a digest mismatch.

        Self {
            _alg: alg,
            state,
            expected,
            segment_index,
            frame_count,
            finalized: false,
        }
    }
    /// Returns a clone of the current internal state for checkpointing.
    pub fn state(&self) -> DigestState {
        self.state.clone() // DigestState must implement Clone
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        debug_assert!(!self.finalized);
        self.state.update(data);
    }

    /// Feed one DATA frame (strictly ascending `frame_index`).
    #[inline]
    pub fn update_frame(&mut self, frame_index: u32, ciphertext: &[u8]) {
        self.update(&frame_index.to_le_bytes());
        self.update(&(ciphertext.len() as u32).to_le_bytes());
        self.update(ciphertext);
        println!("verifier input: seg={} frame_count={} frame_index={} ct_len={}",
            self.segment_index, self.frame_count, frame_index, ciphertext.len());
    }

    /// Finalize and compare against expected digest.
    pub fn finalize(mut self) -> Result<(), DigestError> {
        self.finalized = true;
        let actual = self.state.finalize();
        if actual == self.expected {
            Ok(())
        } else {
            Err(DigestError::DigestMismatch)
        }
    }

}
