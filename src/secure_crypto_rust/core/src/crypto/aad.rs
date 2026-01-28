// ## ✅ Fixed `src/crypto/aad.rs` (parallel-safe, AEAD-correct)

// ## 📂 File: `src/crypto/aad.rs`

use crate::headers::encode_header_le;
use crate::headers::types::{HeaderV1, AadDomain};
use crate::crypto::types::{AadError, AadHeader};

#[inline]
pub fn build_aad(
    header: &HeaderV1,
    aad_header: &AadHeader,
) -> Result<Vec<u8>, AadError> {
    // Validate domain early (domain separation safety)
    if AadDomain::try_from(header.aad_domain).is_err() {
        return Err(AadError::UnknownDomain {
            raw: header.aad_domain,
        });
    }

    let mut out = Vec::with_capacity(AadHeader::LEN_V1);

    // 1️⃣ Authenticate EXACT encoded header bytes (stream-level invariants)
    let header_bytes = encode_header_le(header)?;
    out.extend_from_slice(&header_bytes);

    // 2️⃣ Authenticate ONLY immutable frame invariants
    out.extend_from_slice(&aad_header.frame_type.to_le_bytes());
    out.extend_from_slice(&aad_header.segment_index.to_le_bytes());
    out.extend_from_slice(&aad_header.frame_index.to_le_bytes());
    out.extend_from_slice(&aad_header.plaintext_len.to_le_bytes());

    debug_assert_eq!(out.len(), AadHeader::LEN_V1);
    Ok(out)
}
// ### ✅ AAD is now deterministic and parallel-safe

// AAD is derived **only** from:

// * encoded `HeaderV1` (80 bytes)
// * immutable per-frame metadata

// This guarantees:

// * identical AAD on encrypt + decrypt
// * no cross-worker dependency
// * TLS-style record safety

// ## 📐 Why `FRAME_AAD_LEN` is smaller than `FrameHeader::LEN`

// `FrameHeader::LEN` includes **wire metadata**, not all of which is safe for AAD.

// | Field          | In AAD? | Reason                |
// | -------------- | ------- | --------------------- |
// | frame_type     | ✅       | semantic              |
// | segment_index  | ✅       | ordering              |
// | frame_index    | ✅       | nonce binding         |
// | plaintext_len  | ✅       | truncation protection |
// | compressed_len | ❌       | mutable               |
// | ciphertext_len | ❌       | post-encryption       |

// This separation is **intentional and required**.

// ## 🧠 Final rule (lock this in)

// > **AAD = stream invariants + frame invariants that are known *before* encryption**

// Never deviate from this.
