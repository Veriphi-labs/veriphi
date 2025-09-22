//! Key derivation and small utilities used by veriphi-core.
//!
//! # Overview
//! - **Key generation**: Expand a 32-byte master seed into a permutation of
//!   all 256 byte values using HKDF-SHA256 and a ChaCha20 RNG.
//! - **Utilities**: Unique-value extraction for `u8` slices, and a monotone
//!   IEEE-754 `f32` → `u32` mapping useful for order-preserving hashing.
//!
//! # Security notes
//! - `gen_key` mixes a **fresh 32-byte session id from `OsRng`** on every call,
//!   so results are **non-deterministic** across calls even with the same inputs.
//! - HKDF context labels are **domain-separated** by `party_id`/`purpose`/`session_id`.
//! - This module does **not** provide authenticated encryption on its own.

use hkdf::Hkdf;
use rand::{SeedableRng, seq::SliceRandom};
use rand_chacha::{ChaCha20Rng, rand_core::OsRng, rand_core::TryRngCore};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroize;


/// Generates a permutation of all 256 possible byte values (`0..=255`) using the provided RNG.
///
/// The output is a vector of length 256 containing each value exactly once.
///
/// # Arguments
/// - `rng`: A seeded `ChaCha20Rng` (or any RNG implementing the required traits).
///
/// # Returns
/// A `Vec<u8>` of length 256, representing a random permutation.
#[inline] fn generate_key(rng: &mut ChaCha20Rng) -> [u8; 256] {
    let mut key: [u8; 256] = std::array::from_fn(|i| i as u8);
    key.shuffle(rng);
    return key;
}


/// Expands a 32-byte master seed and context `label` into a `ChaCha20Rng` via **HKDF-SHA256**.
///
/// This provides domain separation: different labels yield independent RNG streams.
///
/// # Arguments
/// - `label`: Arbitrary context bytes (e.g., `party_id:purpose:session_id`).
/// - `master_seed`: 32-byte master seed.
///
/// # Returns
/// A `ChaCha20Rng` deterministically derived from `(master_seed, label)`.
///
/// # Security
/// This is a standard KDF construction (HKDF-SHA256) used to derive RNG state.
/// If `label` is unique per use and `master_seed` has sufficient entropy, outputs are unlinkable.
///
/// # Panics
/// Panics only if HKDF `expand` invariants are violated (should not happen with 32-byte OKM).
fn derive_rng(label: &[u8], master_seed: &[u8; 32]) -> ChaCha20Rng {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm).expect("HKDF expand failed");
    let rng = ChaCha20Rng::from_seed(okm);
    okm.zeroize(); 
    return rng;
}

/// Builds a domain-separated label by mixing `party_id`, `purpose`, and a `session_id`.
///
/// The label is used as HKDF context to avoid key/stream reuse.
///
/// # Arguments
/// - `party_id`: Logical owner/role, e.g., `"authoriser"`.
/// - `purpose`: Short purpose string, e.g., `"private_key"`.
/// - `session_id`: Random 32-byte nonce/identifier.
///
/// # Returns
/// Byte vector suitable as HKDF `info`/context.
#[inline] fn make_label(party_id: &str, purpose: &str, session_id: &[u8]) -> Vec<u8> {
    let mut label = format!("veriphi:{}:{}", party_id, purpose).into_bytes();
    label.extend_from_slice(session_id);
    return label;
}

/// Error type for random number generation failures.
///
/// At present, the only possible error is when the operating system's
/// cryptographically secure random number generator (`OsRng`) is
/// unavailable.
///
/// Such failures are extremely rare on modern platforms, but are
/// exposed here so callers can handle them explicitly.
#[derive(thiserror::Error, Debug)]
pub enum RandError {
    /// The operating system's RNG could not provide randomness.
    #[error("OS RNG unavailable")]
    OsRng,
}

/// Attempts to produce a cryptographically random 32-byte session identifier
/// using the operating system’s CSPRNG.
///
/// # Returns
/// - `Ok([u8; 32])` containing a freshly generated random identifier.
/// - `Err(RandError::OsRng)` if the OS RNG is unavailable.
///
/// # Security
/// - Generated identifiers are suitable for use as nonces, session tokens,
///   or domain-separating inputs in key derivation.
/// - Randomness is sourced directly from the OS and is cryptographically strong.
///
/// # Example
/// ```
/// # use veriphi_core::utils::try_generate_session_id;
/// match try_generate_session_id() {
///     Ok(session_id) => assert_eq!(session_id.len(), 32),
///     Err(e) => eprintln!("RNG error: {e}"),
/// }
/// ```
pub fn try_generate_session_id() -> Result<[u8; 32], RandError> {
    let mut session_id = [0u8; 32];
    OsRng.try_fill_bytes(&mut session_id).map_err(|_| RandError::OsRng)?;
    Ok(session_id)
}

/// Produces a cryptographically random 32-byte session identifier using
/// the operating system’s CSPRNG.
///
/// This is a convenience wrapper around [`try_generate_session_id`] that
/// panics if randomness is unavailable.
///
/// # Panics
/// Panics with `"OS RNG unavailable"` if the operating system cannot
/// provide random bytes (extremely rare).
///
/// # Security
/// - Identical guarantees to [`try_generate_session_id`].
/// - Recommended for typical use when you prefer ergonomics over explicit
///   error handling.
///
/// # Example
/// ```
/// # use veriphi_core::utils::generate_session_id;
/// let session_id = generate_session_id();
/// assert_eq!(session_id.len(), 32);
/// ```
pub fn generate_session_id() -> [u8; 32] {
    try_generate_session_id().expect("OS RNG unavailable")
}

/// Generates a fresh **256-byte permutation key** by deriving a ChaCha20 RNG from the master seed.
///
/// A **random session id** is mixed into the HKDF label so repeated calls yield distinct keys,
/// even with identical inputs.
///
/// # Arguments
/// - `party_id`: Domain separator (e.g., role or component id).
/// - `purpose`: Domain separator for the specific use.
/// - `master_seed`: 32-byte master seed.
///
/// # Returns
/// A `Vec<u8>` of length 256: a permutation of all byte values.
///
/// # Security
/// - Non-deterministic across calls due to a fresh `session_id`.
/// - Backed by HKDF-SHA256 and ChaCha20 RNG.
///
/// # Example
/// ```
/// # use veriphi_core::utils::gen_key; 
/// # use rand_chacha::ChaCha20Rng;
/// # use rand::SeedableRng;
/// # let master = [7u8; 32];
/// let key = gen_key("A", "private_key", &master);
/// assert_eq!(key.len(), 256);
/// assert!(key.iter().copied().collect::<std::collections::HashSet<u8>>().len() == 256);
/// ```
pub fn gen_key(party_id: &str, purpose: &str, master_seed: &[u8; 32]) -> [u8; 256] {
    let session_id = generate_session_id();
    let mut gen_rng = derive_rng(&make_label(party_id, purpose, &session_id), &master_seed);
    return generate_key(&mut gen_rng);
}

/// Generates a **deterministic** 256-byte permutation key from a master seed and
/// a caller-provided `session_id`.
///
/// Unlike [`gen_key`], this does **not** call `OsRng`; the output is fully
/// determined by `(party_id, purpose, master_seed, session_id)`. This is ideal
/// for tests, reproducible builds, or deriving stable keys across processes.
///
/// Internally derives a `ChaCha20Rng` via **HKDF-SHA256** using a domain-separated
/// label constructed from `party_id`, `purpose`, and `session_id`, then shuffles
/// the bytes `0..=255` to produce a permutation.
///
/// # Arguments
/// - `party_id`: Domain separator (e.g., role or component id).
/// - `purpose`: Domain separator for the specific use (e.g., `"private_key"`).
/// - `master_seed`: 32-byte master seed.
/// - `session_id`: 32-byte identifier/nonce to make the derivation deterministic.
///
/// # Returns
/// A `Vec<u8>` of length 256: a permutation of all byte values.
///
/// # Security
/// Deterministic by design. Use only when reproducibility is required.
/// For production where uniqueness across calls is desired, prefer [`gen_key`]
/// which mixes a fresh random `session_id`.
///
/// # Example
/// ```
/// # use veriphi_core::utils::gen_key_deterministic;
/// # let master = [7u8; 32];
/// # let session = [9u8; 32];
/// let key1 = gen_key_deterministic("A", "private_key", &master, &session);
/// let key2 = gen_key_deterministic("A", "private_key", &master, &session);
/// assert_eq!(key1, key2);                 // same inputs → same output
/// assert_eq!(key1.len(), 256);
/// ```
pub fn gen_key_deterministic(party_id: &str, purpose: &str, master_seed: &[u8; 32], session_id: &[u8; 32]) -> [u8; 256] {
    let mut rng = derive_rng(&make_label(party_id, purpose, session_id), master_seed);
    generate_key(&mut rng)
}


/// Returns the **sorted list of unique byte values** in `data` and a map from value to its index.
///
/// The vector is sorted ascending and deduplicated; the `HashMap` maps each unique `u8` to its
/// index in that vector.
///
/// # Arguments
/// - `data`: Input slice of bytes.
///
/// # Returns
/// `(unique_values, index_map)`:
/// - `unique_values`: `Vec<u8>` sorted ascending, no duplicates.
/// - `index_map`: `HashMap<u8, usize>` so `index_map[&value]` gives the position in `unique_values`.
///
/// # Complexity
/// `O(n log n)` due to sorting.
///
/// # Example
/// ```
/// # use veriphi_core::utils::unique_vals;        
/// let (vals, idx) = unique_vals(&[5, 2, 5, 9, 2]);
/// assert_eq!(vals, vec![2, 5, 9]);
/// assert_eq!(idx[&2], 0);
/// assert_eq!(idx[&5], 1);
/// assert_eq!(idx[&9], 2);
/// ```
pub fn unique_vals(data: &[u8]) -> (Vec<u8>, HashMap<u8, usize>) {
    let mut unique_data: Vec<u8> = data.to_vec();
    unique_data.sort_unstable();
    unique_data.dedup();

    let index_map: HashMap<u8, usize> = unique_data
        .iter()
        .enumerate()
        .map(|(i, &val)| (val, i))
        .collect();

    return (unique_data, index_map);
}

/// Reinterprets an `f32` as `u32` so **integer ordering matches IEEE-754 total order** over `f32`.
///
/// This is useful when you need a stable, order-preserving integer encoding of floats
/// (e.g., for order-preserving hashing or sorting in byte-oriented contexts).
///
/// - Preserves relative order of all finite values.
/// - NaNs: All NaN payloads map to a range above/below finite numbers depending on sign bit.
/// - Endianness-independent (uses `to_bits()`).
///
/// # Example
/// ```
/// # use veriphi_core::utils::float_to_ordered_u32; 
/// let a = 1.0f32;
/// let b = 2.0f32;
/// assert!(float_to_ordered_u32(a) < float_to_ordered_u32(b));
/// let neg = -0.0f32;
/// let pos = 0.0f32;
/// assert!(float_to_ordered_u32(neg) < float_to_ordered_u32(pos));
/// ```
pub fn float_to_ordered_u32(f: f32) -> u32 {
    let bits = f.to_bits();
    if bits & 0x8000_0000 != 0 {
        return !bits;
    } else {
        return bits ^ 0x8000_0000;
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::HashSet;

    fn is_perm_0_to_255(v: &[u8]) -> bool {
        v.len() == 256 && v.iter().copied().collect::<HashSet<_>>().len() == 256
    }

    #[test]
    fn generate_key_is_permutation() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let key = generate_key(&mut rng);
        assert!(is_perm_0_to_255(&key));
    }

    #[test]
    fn derive_rng_is_deterministic_for_same_inputs() {
        let master = [1u8; 32];
        let label = b"veriphi:A:private_key\x00\x01\x02";
        let mut rng1 = derive_rng(label, &master);
        let mut rng2 = derive_rng(label, &master);

        // Using the RNGs to produce keys should match exactly
        let k1 = generate_key(&mut rng1);
        let k2 = generate_key(&mut rng2);
        assert_eq!(k1, k2);
        assert!(is_perm_0_to_255(&k1));
    }

    #[test]
    fn make_label_formats_and_contains_session_suffix() {
        let session = [1u8, 2, 3, 4];
        let lbl = make_label("A", "private_key", &session);
        assert!(lbl.starts_with(b"veriphi:A:private_key"));
        assert!(lbl.ends_with(&session));
    }

    #[test]
    fn generate_session_id_is_32_bytes_and_nonzero() {
        let sid = generate_session_id();
        assert_eq!(sid.len(), 32);
        // Not all zeros (extremely unlikely with a real CSPRNG)
        assert!(sid.iter().any(|&b| b != 0));
    }

    #[test]
    fn gen_key_deterministic_is_stable_and_varies_with_session() {
        let master = [7u8; 32];
        let s1 = [9u8; 32];
        let s2 = [8u8; 32];

        let k1 = gen_key_deterministic("A", "private_key", &master, &s1);
        let k1_again = gen_key_deterministic("A", "private_key", &master, &s1);
        let k2 = gen_key_deterministic("A", "private_key", &master, &s2);

        assert_eq!(k1, k1_again);
        assert!(is_perm_0_to_255(&k1));
        assert!(is_perm_0_to_255(&k2));
        assert_ne!(k1, k2); // different session → different permutation
    }

    #[test]
    fn gen_key_produces_valid_permutation() {
        let master = [3u8; 32];
        // Non-deterministic across calls by design (fresh session id),
        // so just check validity, not inequality.
        let k = gen_key("A", "private_key", &master);
        assert!(is_perm_0_to_255(&k));
    }

    #[test]
    fn unique_vals_returns_sorted_unique_and_index_map() {
        let (vals, idx) = unique_vals(&[5, 2, 5, 9, 2, 7, 7, 0]);
        assert_eq!(vals, vec![0, 2, 5, 7, 9]);
        assert_eq!(idx[&0], 0);
        assert_eq!(idx[&2], 1);
        assert_eq!(idx[&5], 2);
        assert_eq!(idx[&7], 3);
        assert_eq!(idx[&9], 4);
    }

    #[test]
    fn float_to_ordered_u32_preserves_order_for_common_cases() {
        let a = -0.0f32;
        let b = 0.0f32;
        let c = 1.0f32;
        let d = 2.0f32;

        assert!(float_to_ordered_u32(a) < float_to_ordered_u32(b));
        assert!(float_to_ordered_u32(b) < float_to_ordered_u32(c));
        assert!(float_to_ordered_u32(c) < float_to_ordered_u32(d));

        // Random spot check around negatives
        let n1 = -10.5f32;
        let n2 = -1.25f32;
        assert!(float_to_ordered_u32(n1) < float_to_ordered_u32(n2));
    }

    #[test]
    fn float_to_ordered_u32_edge_cases() {
        let ninf = f32::NEG_INFINITY;
        let pinf = f32::INFINITY;
        assert!(float_to_ordered_u32(ninf) < float_to_ordered_u32(-1.0));
        assert!(float_to_ordered_u32(1.0)   < float_to_ordered_u32(pinf));
        let nan1 = f32::NAN;
        let nan2 = f32::from_bits(0x7fc0_0001);
        // No total order guarantee across all NaN payloads; just ensure mapping is deterministic:
        assert_eq!(float_to_ordered_u32(nan1), float_to_ordered_u32(nan1));
        assert_ne!(float_to_ordered_u32(nan1), float_to_ordered_u32(1.0));
        assert_ne!(float_to_ordered_u32(nan1), float_to_ordered_u32(ninf));
        // Distinct NaNs may map differently (expected):
        let _ = (nan1, nan2);
    }
}