use std::{convert::TryFrom};
use sha2::{
    Digest as _,
    Sha256, Sha512,
};
use blake3;

/// Digest-related errors.
#[derive(Debug)]
pub enum DigestError {
    UnknownAlgorithm(u16),
    InvalidLength { expected: usize, actual: usize },
    DigestMismatch,
    InvalidFormat,
}

/// Supported digest algorithms (extensible).
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DigestAlg {
    Sha256 = 0x0001,
    Sha512 = 0x0002,
    Blake3 = 0x0003, // UNKEYED Blake3
}

// impl TryFrom<u8> for DigestAlg {
//     type Error = DigestError;

//     fn try_from(value: u8) -> Result<Self, Self::Error> {
//         match value {
//             0x01 => Ok(DigestAlg::Sha256),
//             0x02 => Ok(DigestAlg::Sha512),
//             0x03 => Ok(DigestAlg::Blake3),
//             _ => Err(DigestError::UnknownAlgorithm(value)),
//         }
//     }
// }
impl TryFrom<u16> for DigestAlg {
    type Error = DigestError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(DigestAlg::Sha256),
            0x0002 => Ok(DigestAlg::Sha512),
            0x0003 => Ok(DigestAlg::Blake3),
            _ => Err(DigestError::UnknownAlgorithm(value)),
        }
    }
}

/// Internal hashing state.
pub enum DigestState {
    Sha256(Sha256),
    Sha512(Sha512),
    Blake3(blake3::Hasher),
}

impl DigestState {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        match self {
            DigestState::Sha256(h) => h.update(data),
            DigestState::Sha512(h) => h.update(data),
            // Blake3 update returns &mut Hasher, we ignore it here
            DigestState::Blake3(h) => { h.update(data); },
            // Explicitly discard the &mut Hasher return value
            // DigestState::Blake3(h) => { let _ = h.update(data); },
        }
    }

    #[inline]
    fn finalize(self) -> Vec<u8> {
        match self {
            DigestState::Sha256(h) => h.finalize().to_vec(),
            DigestState::Sha512(h) => h.finalize().to_vec(),
            DigestState::Blake3(h) => h.finalize().as_bytes().to_vec(),
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
        let algorithm = DigestAlg::try_from(alg_id)?;

        let length = u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize;
        let actual = plaintext.len() - 4;

        if length != actual {
            return Err(DigestError::InvalidLength {
                expected: length,
                actual,
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
/// segment_index   (u64 LE)
/// frame_count     (u32 LE)
/// for each DATA frame, ordered by frame_index:
///   frame_index   (u32 LE)
///   ciphertext_len(u32 LE)
///   ciphertext    (N bytes)
/// ```
pub struct DigestBuilder {
    alg: DigestAlg,
    state: DigestState,
    segment_index: u64,
    frame_count: u32,
    finalized: bool,
}
impl DigestBuilder {
    /// Create a new digest builder.
    #[inline]
    pub fn new(alg: DigestAlg) -> Self {
        let state = match alg {
            DigestAlg::Sha256 => DigestState::Sha256(Sha256::new()),
            DigestAlg::Sha512 => DigestState::Sha512(Sha512::new()),
            DigestAlg::Blake3 => DigestState::Blake3(blake3::Hasher::new()),
        };

        Self {
            alg,
            state,
            segment_index: 0,
            frame_count: 0,
            finalized: false,
        }
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        debug_assert!(!self.finalized);
        self.state.update(data);
    }

    /// Feed segment header (exactly once).
    #[inline]
    pub fn start_segment(&mut self, segment_index: u64, frame_count: u32) {
        self.segment_index = segment_index;
        self.frame_count = frame_count;
        self.update(&segment_index.to_le_bytes());
        self.update(&frame_count.to_le_bytes());
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
    alg: DigestAlg,
    state: DigestState,
    expected: Vec<u8>,
    segment_index: u64,
    frame_count: u32,
    finalized: bool,
}

impl SegmentDigestVerifier {
    pub fn new(
        alg: DigestAlg,
        segment_index: u64,
        frame_count: u32,
        expected: Vec<u8>,
    ) -> Self {
        let mut state = match alg {
            DigestAlg::Sha256 => DigestState::Sha256(Sha256::new()),
            DigestAlg::Sha512 => DigestState::Sha512(Sha512::new()),
            DigestAlg::Blake3 => DigestState::Blake3(blake3::Hasher::new()),
        };

        state.update(&segment_index.to_le_bytes());
        state.update(&frame_count.to_le_bytes());

        Self {
            alg,
            state,
            expected,
            segment_index,
            frame_count,
            finalized: false,
        }
    }

    #[inline]
    pub fn update_frame(&mut self, frame_index: u32, ciphertext: &[u8]) {
        debug_assert!(!self.finalized);
        self.state.update(&frame_index.to_le_bytes());
        self.state.update(&(ciphertext.len() as u32).to_le_bytes());
        self.state.update(ciphertext);
        println!("verifier input: seg={} frame_count={} frame_index={} ct_len={}",
            self.segment_index, self.frame_count, frame_index, ciphertext.len());
    }

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
