// # Rust headers module layout

// Below are production-ready files for src/headers/, designed to be the single source of truth for our envelope header. 
// They include explicit enums, constants, types, encoding/decoding helpers, validation, and tests. 
// The header is 80 bytes, fixed-length, future-proof, and aligned with industry practices (AAD binding, key ID, salt, algorithm profile, flags, strategy).

// ## src/headers/mod.rs

//! headers/mod.rs
//! Public module export for the streaming envelope headers.
//!
//! Industry notes:
//! - Fixed-size header (80 bytes) enables deterministic IO and simple embedding.
//! - Explicit IDs (cipher, PRF, compression, strategy) avoid silent incompatibilities.
//! - Key ID and salt align with HSM/KMS practices: stream points to key version, secrets stay external.
//! - Flags declare presence of optional metadata (totals, CRC, terminator/digest frames).
//! - AAD domain binds header semantics into per-frame AEAD AAD, preventing cross-protocol confusion.

pub mod types;
pub mod encode;
pub mod decode;

pub use types::*;
pub use encode::*;
pub use decode::*;

// ## Implementation notes

// - Endianness: Little-endian across all multi-byte integers; document this in our Python mirror when we clone the Rust project.
// - Security: The header is authenticated indirectly via AAD in each frame; never trust header fields without AEAD verification. Flags only guide optional behavior.
// - Extensibility: Use the reserved field for future additions (e.g., signing policy IDs, attestation markers). Bump version when semantics change.
// - Parity: Keep these files authoritative. Bindings (Python, etc.) should import the constants and replicate binary layouts exactly.
