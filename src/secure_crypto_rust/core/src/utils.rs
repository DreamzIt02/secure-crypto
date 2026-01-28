use std::fmt;
use num_enum::TryFromPrimitive;

use crate::{constants::{ALLOWED_CHUNK_SIZES, ChunkPolicy, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, RoundingBase}};

#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum ChecksumAlg {
    Crc32   = 0x0001,
    Blake3   = 0x0201, // UN-KEYED Blake3
}
pub fn compute_checksum(data: &[u8], alg: Option<ChecksumAlg>) -> u32 {
    match alg {
        Some(ChecksumAlg::Crc32)  => compute_crc32(data),
        // Some(ChecksumAlg::Blake3) => compute_blake3(data), // Its return 32-bytes
        _                         => compute_crc32(data)
    }
}

fn compute_crc32(data: &[u8]) -> u32 {
    use crc32fast::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

// fn compute_blake3(data: &[u8]) -> [u8; 32] {
//     use blake3::Hasher;
//     let mut hasher = Hasher::new();
//     hasher.update(data);
//     *hasher.finalize().as_bytes()
// }

pub fn enum_name_or_hex<T>(raw: T::Primitive) -> String
where
    T: TryFromPrimitive + fmt::Debug,
    T::Primitive: fmt::LowerHex,
{
    match T::try_from_primitive(raw) {
        Ok(variant) => format!("{:?}", variant),
        Err(_) => format!("0x{:x}", raw),
    }
}

// Helper function to flatten frames into single plaintext blob
pub fn frames_to_plaintext(frames: &[impl AsRef<[u8]>]) -> Vec<u8> {
    frames.iter()
        .flat_map(|f| f.as_ref())
        .copied()
        .collect()
}

pub fn best_chunk_size(
    requested: Option<usize>,
    policy: ChunkPolicy,
    rounding_base: RoundingBase,
) -> usize {
    match requested {
        None => DEFAULT_CHUNK_SIZE,
        Some(size) => {
            if size > MAX_CHUNK_SIZE {
                return MAX_CHUNK_SIZE;
            }
            if ALLOWED_CHUNK_SIZES.contains(&size) {
                return size;
            }

            let max_allowed = *ALLOWED_CHUNK_SIZES.iter().max().unwrap();
            let min_allowed = *ALLOWED_CHUNK_SIZES.iter().min().unwrap();

            if size < min_allowed {
                return min_allowed;
            }

            if size > max_allowed {
                return dynamic_industry_standard(size, max_allowed, MAX_CHUNK_SIZE, policy, rounding_base);
            }

            // Fallback to ALLOWED_CHUNK_SIZES logic
            match policy {
                ChunkPolicy::RoundUp => {
                    for &allowed in ALLOWED_CHUNK_SIZES {
                        if size <= allowed {
                            return allowed;
                        }
                    }
                    max_allowed
                }
                ChunkPolicy::RoundDown => {
                    let mut candidate = min_allowed;
                    for &allowed in ALLOWED_CHUNK_SIZES {
                        if allowed <= size {
                            candidate = allowed;
                        } else {
                            break;
                        }
                    }
                    candidate
                }
                ChunkPolicy::Nearest { tolerance } => {
                    let mut closest = min_allowed;
                    let mut min_diff = (size as isize - closest as isize).abs();
                    for &allowed in ALLOWED_CHUNK_SIZES {
                        let diff = (size as isize - allowed as isize).abs();
                        if diff < min_diff {
                            min_diff = diff;
                            closest = allowed;
                        }
                    }
                    let rel_diff = min_diff as f32 / size as f32;
                    if rel_diff <= tolerance {
                        closest
                    } else {
                        for &allowed in ALLOWED_CHUNK_SIZES {
                            if size <= allowed {
                                return allowed;
                            }
                        }
                        max_allowed
                    }
                }
            }
        }
    }
}

/// Dynamically compute industry-standard chunk sizes above max_allowed.
/// Uses binary multiples and logarithmic fallback with configurable rounding base.
fn dynamic_industry_standard(
    size: usize,
    max_allowed: usize,
    max_chunk: usize,
    policy: ChunkPolicy,
    rounding_base: RoundingBase,
) -> usize {
    let mut candidates = Vec::new();
    let mut current = max_allowed * 2;
    while current <= max_chunk {
        candidates.push(current);
        current *= 2;
    }

    // Logarithmic fallback: nearest power of two in chosen base
    let unit = rounding_base.to_unit();
    let size_in_units = (size as f64 / unit as f64).round() as usize;
    let log2_size = (size_in_units as f64).log2().round() as u32;

    // Cap exponent
    let capped_exp = log2_size.min(rounding_base.max_exponent());
    let pow2_units = 1usize << capped_exp;
    let pow2_bytes = pow2_units * unit;

    if pow2_bytes <= max_chunk {
        candidates.push(pow2_bytes);
    }

    candidates.sort_unstable();
    candidates.dedup();

    match policy {
        ChunkPolicy::RoundUp => {
            for &c in candidates.iter() {
                if size <= c {
                    return c;
                }
            }
            *candidates.last().unwrap_or(&max_allowed)
        }
        ChunkPolicy::RoundDown => {
            let mut candidate = max_allowed;
            for &c in candidates.iter() {
                if c <= size {
                    candidate = c;
                } else {
                    break;
                }
            }
            candidate
        }
        ChunkPolicy::Nearest { tolerance } => {
            let mut closest = max_allowed;
            let mut min_diff = (size as isize - closest as isize).abs();
            for &c in candidates.iter() {
                let diff = (size as isize - c as isize).abs();
                if diff < min_diff {
                    min_diff = diff;
                    closest = c;
                }
            }
            let rel_diff = min_diff as f32 / size as f32;
            if rel_diff <= tolerance {
                closest
            } else {
                for &c in candidates.iter() {
                    if size <= c {
                        return c;
                    }
                }
                *candidates.last().unwrap_or(&max_allowed)
            }
        }
    }
}

// ### 🔑 Example Configurations
// - `RoundingBase::MiB { max_exp: 20 }` → powers of two up to 2²⁰ MiB = 1 MiB × 2²⁰ = ~1 TiB.  
// - `RoundingBase::KiB { max_exp: 20 }` → powers of two up to 2²⁰ KiB = ~1 GiB.  
// - `RoundingBase::Bytes { max_exp: 32 }` → powers of two up to 2³² bytes = 4 GiB.  

// ### Behavior Example
// - Request = 23 MiB, `RoundingBase::MiB { max_exp: 20 }` → nearest fallback = 24 MiB.  
// - Request = 40 MiB, `RoundingBase::MiB { max_exp: 5 }` → capped at 32 MiB (since 2⁵ = 32).  
// - Request = 70 MiB, `MAX_CHUNK_SIZE = 64 MiB` → clamps to 64 MiB.  

// This makes the helper **fully configurable**:  
// - We control **policy** (RoundUp, RoundDown, Nearest).  
// - We control **unit scale** (Bytes, KiB, MiB).  
// - We control **maximum exponent** to cap fallback growth.  
