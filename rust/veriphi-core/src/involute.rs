use hmac::{Hmac, Mac};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

use crate::utils::*;

/// Errors that appear in the involute function
#[derive(Error, Debug, PartialEq)]
pub enum InvoluteError {
    #[error("Packet length ({packet_len}) is not a multiple of chunk size ({chunk_size}).")]
    InvalidPacketSize {
        packet_len: usize,
        chunk_size: usize,
    },
    #[error("Duplicate crumbs detected after operations, cannot create a unique pattern")]
    DuplicateCrumbs,
}

/// Computes the SHA-256 hash of the input packet after sorting its bytes.
///
/// # Arguments
///
/// * `packet` - A byte slice representing the input data to hash.
///
/// # Returns
///
/// A 32-byte array containing the SHA-256 digest of the sorted packet bytes.
///
fn full_packet_hash(packet: &[u8]) -> [u8; 32] {
    let mut sorted = packet.to_vec();
    sorted.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(&sorted);
    let digest = hasher.finalize();
    return digest.into();
}

/// Performs a deterministic permutation ("involution") on the input packet data
/// based on a provided salt and chunk size. The packet is split into chunks,
/// each chunk's hash is combined with the salt and the full packet fingerprint,
/// and a permutation is computed from these hashes to reorder the chunks.
///
/// # Arguments
///
/// * `packet` - The input packet data as a byte slice.
/// * `salt` - A byte slice used as salt to alter chunk hashes.
/// * `chunk_size` - The size of each chunk; must be > 0 and divide the packet length.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The permuted packet as a vector of bytes, if successful.
/// * `Err(InvoluteError)` - If the packet size is invalid or duplicate chunk hashes are found.
///
/// # Errors
///
/// Returns `InvoluteError::InvalidPacketSize` if `chunk_size` does not evenly divide the packet length.
/// Returns `InvoluteError::DuplicateCrumbs` if duplicate chunk digests are detected.
///
/// # Notes
///
/// - If `chunk_size` is zero, returns the original packet unchanged.
/// - If the input packet is empty, returns an empty vector.
pub fn involute_packet(
    packet: &[u8],
    salt: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, InvoluteError> {
    let (low_bound, high_bound, test_value) = get_cond_defaults(salt);
    return Ok(cond_involute_packet(
        packet, salt, chunk_size, low_bound, high_bound, test_value,
    ))?;
    // The above function is a wrapper that calls the main involute function with default bounds and
    // a test value of 0.0, which means it will not filter out any
}

/// Generate default bounds for the involute function, returning the hashed data based on
/// the provided salt.
/// # Arguments
/// * `salt` - A byte slice used as salt to alter the hash values.
/// # Returns
/// A tuple containing:
/// - `low_embed`: The hashed value for the lower bound (-1.0).
/// - `high_embed`: The hashed value for the upper bound (1.0).
/// - `test_value`: A test value of 0.0,
fn get_cond_defaults(salt: &[u8]) -> (u64, u64, f32) {
    let (low_embed, high_embed) = prep_condition(-1.0f32, 1.0f32, salt);
    return (low_embed, high_embed, 0.0f32);
}

/// Determines the minimal valid chunk size for splitting a byte packet into
/// unique, non-overlapping segments.
///
/// The function scans for the smallest chunk size `≥ min_val` that divides the
/// packet length evenly and results in **all chunks being unique**.  
/// If no such chunk size exists, the function falls back to the full packet
/// length. Special cases:
/// - Empty input returns `0`.
/// - If the packet length is less than `2 * min_val`, the packet length is returned.
///
/// # Arguments
/// - `packet`: Input data slice to be analyzed.
/// - `min_val`: The minimum allowed chunk size to consider.
///
/// # Returns
/// The chosen chunk size in bytes:
/// - `0` if the packet is empty.
/// - Otherwise, the smallest valid chunk size that yields unique chunks, or the
///   full packet length if none qualifies.
///
/// # Example
/// ```
/// # use veriphi_core::involute::get_chunk_size_min;
/// let packet = b"abcdefgh"; // length 8
/// let chunk_size = get_chunk_size_min(packet, 2);
/// assert_eq!(chunk_size, 2); // "ab","cd","ef","gh" are all unique
///
/// let packet = b"aaaabbbb"; // length 8
/// let chunk_size = get_chunk_size_min(packet, 2);
/// assert_eq!(chunk_size, 4); // sub-packets are unique
///
/// let empty: &[u8] = &[];
/// assert_eq!(get_chunk_size_min(empty, 2), 0);
/// ```
pub fn get_chunk_size_min(packet: &[u8], min_val: usize) -> usize {
    if packet.is_empty() {
        // If the packet is empty, return 0 as the chunk size
        return 0;
    }
    let mut final_chunk_size = packet.len();
    let packet_size: usize = packet.len();
    if (packet_size / 2) < min_val {
        // If the packet size is less than the minimum value, return the packet size
        return packet_size;
    }
    for chunk_size in min_val..=(packet_size / 2) {
        if packet_size % chunk_size != 0 {
            continue;
        }
        let num_chunks = packet_size / chunk_size;
        let mut seen = HashSet::with_capacity(num_chunks);
        let mut unique = true;
        for i in 0..num_chunks {
            let chunk = &packet[i * chunk_size..(i + 1) * chunk_size];
            if !seen.insert(chunk) {
                unique = false;
                break;
            }
        }
        if unique {
            final_chunk_size = chunk_size;
            break;
        }
    }
    return final_chunk_size;
}

/// Determines the smallest valid chunk size (≥ 4 bytes) that divides a packet
/// evenly into **unique, non-overlapping chunks**.
///
/// The function scans from chunk size `4` up to half the packet length, looking
/// for the first size that divides the packet evenly and yields unique chunks.
/// If no such size is found, the full packet length is returned.  
/// Special cases:
/// - Empty input returns `0`.
///
/// # Arguments
/// - `packet`: Input data slice to be analyzed.
///
/// # Returns
/// The chosen chunk size in bytes:
/// - `0` if the packet is empty.
/// - Otherwise, the smallest valid chunk size (≥ 4) that yields unique chunks,
///   or the full packet length if none qualifies.
///
/// # Example
/// ```
/// # use veriphi_core::involute::get_chunk_size;
/// let packet = b"abcdefgh"; // length 8
/// let chunk_size = get_chunk_size(packet);
/// assert_eq!(chunk_size, 4); // "abcd","efgh" are uniquem and 4 is the minimum size
///
/// let packet = b"aaaabbbb"; // length 8
/// let chunk_size = get_chunk_size(packet);
/// assert_eq!(chunk_size, 4); // only whole-packet is unique
///
/// let empty: &[u8] = &[];
/// assert_eq!(get_chunk_size(empty), 0);
/// ```
pub fn get_chunk_size(packet: &[u8]) -> usize {
    if packet.is_empty() {
        return 0;
    }
    let mut final_chunk_size = packet.len();
    let packet_size: usize = packet.len();
    // A default that we work on smallest chunks of 4 bytes
    for chunk_size in 4..=(packet_size / 2) {
        if packet_size % chunk_size != 0 {
            continue;
        }
        let num_chunks = packet_size / chunk_size;
        let mut seen = HashSet::with_capacity(num_chunks);
        let mut unique = true;
        for i in 0..num_chunks {
            let chunk = &packet[i * chunk_size..(i + 1) * chunk_size];
            if !seen.insert(chunk) {
                unique = false;
                break;
            }
        }
        if unique {
            final_chunk_size = chunk_size;
            break;
        }
    }
    return final_chunk_size;
}

/// Performs a **conditional, deterministic permutation** (“involution”) of `packet`
/// using a per-chunk digest mixed with `salt` and a condition value derived from
/// (`low_bound`, `high_bound`, `test_value`).
///
/// The input is split into `chunk_size`-byte chunks. For each chunk we compute
/// `SHA256(chunk || salt)`, XOR it with a **fingerprint** of `packet || cond`
/// (where `cond` is derived via [`cond_hash_branch`]), and sort by that digest to
/// obtain a permutation. A second permutation layer (`p[p[i]]`) is applied to
/// strengthen mixing. The result is a byte-for-byte **permutation** of the input
/// (no bytes are created or lost).
///
/// This function is **deterministic** for fixed inputs: the same `(packet, salt,
/// chunk_size, low_bound, high_bound, test_value)` always yields the same output.
/// Parallelism via Rayon is used internally, but the output order is stable.
///
/// > **Note:** This is not encryption or authentication. It’s a keyed, reversible
/// > permutation intended for obfuscation and ordering effects. Use an AEAD for
/// > confidentiality/integrity.
///
/// # Arguments
/// - `packet`: Input bytes to permute; must be evenly divisible by `chunk_size`.
/// - `salt`: Keying material that influences the permutation.
/// - `chunk_size`: Chunk size in bytes. If `0`, the function returns `packet` unchanged.
/// - `low_bound`, `high_bound`: Encoded bounds for a condition window (see
///   [`prep_condition`]); must satisfy `low_bound <= high_bound`.
/// - `test_value`: Floating value tested against the window via [`cond_hash_branch`];
///   it influences the fingerprint and thus the permutation.
///
/// # Returns
/// - `Ok(Vec<u8>)` with the permuted bytes on success.
/// - `Err(InvoluteError::InvalidPacketSize { .. })` if `packet.len()` is not a multiple of `chunk_size`.
/// - `Err(InvoluteError::DuplicateCrumbs)` if per-chunk digests are not unique (extremely rare except for adversarial inputs).
///
/// # Examples
/// Basic usage with a valid `chunk_size` and condition window:
/// ```
/// # use veriphi_core::involute::{cond_involute_packet, prep_condition, get_chunk_size, InvoluteError};
/// let packet = b"The quick brown fox jumps over the lazy dog";
/// let salt   = b"veriphi-salt";
/// // Pick a chunk size that divides the packet cleanly:
/// let chunk = get_chunk_size(packet);
/// let (lo, hi) = prep_condition(-1.0, 1.0, salt);
/// // Any test value is allowed; it conditions the permutation:
/// let out = cond_involute_packet(packet, salt, chunk, lo, hi, 0.0).expect("permute");
/// assert_eq!(out.len(), packet.len());
/// // It's a permutation: same multiset of bytes (simple length check here).
/// ```
///
/// Error when `chunk_size` doesn’t divide the packet:
/// ```
/// # use veriphi_core::involute::{cond_involute_packet, prep_condition, InvoluteError};
/// let packet = b"abc";                         // len = 3
/// let salt   = b"salt";
/// let (lo, hi) = prep_condition(-1.0, 1.0, salt);
/// let err = cond_involute_packet(packet, salt, 4, lo, hi, 0.0).unwrap_err();
/// match err {
///     InvoluteError::InvalidPacketSize { packet_len, chunk_size } => {
///         assert_eq!(packet_len, 3);
///         assert_eq!(chunk_size, 4);
///     }
///     other => panic!("unexpected error: {other:?}"),
/// }
/// ```
pub fn cond_involute_packet(
    packet: &[u8],
    salt: &[u8],
    chunk_size: usize,
    low_bound: u64,
    high_bound: u64,
    test_value: f32,
) -> Result<Vec<u8>, InvoluteError> {
    if chunk_size == 0 {
        // If chunk size is zero, return the packet as is
        return Ok(packet.to_vec());
    }
    if packet.len() % chunk_size != 0 {
        // Check for incongruent chunk and packet sizes
        return Err(InvoluteError::InvalidPacketSize {
            packet_len: packet.len(),
            chunk_size,
        });
    }
    if packet.is_empty() {
        // If the packet is empty, return an empty vector
        return Ok(Vec::new());
    }
    let num_chunks = packet.len() / chunk_size;

    let cond = cond_hash_branch(low_bound, high_bound, test_value, salt);
    let mut cond_packet = Vec::with_capacity(packet.len() + 8);
    cond_packet.extend_from_slice(packet);
    cond_packet.extend_from_slice(&cond.to_be_bytes());
    let fingerprint = full_packet_hash(cond_packet.as_slice());
    let mut indexed_digests: Vec<(usize, [u8; 32])> = (0..num_chunks)
        .into_par_iter()
        .map(|i| {
            let start = i * chunk_size;
            let end = start + chunk_size;
            let chunk = &packet[start..end];

            let mut hasher = Sha256::new();
            hasher.update(chunk);
            hasher.update(salt);

            let chunk_digest = hasher.finalize();

            // Now XOR with the fingerprint
            let mut xored_digest = [0u8; 32];
            for i in 0..32 {
                xored_digest[i] = chunk_digest[i] ^ fingerprint[i];
            }

            (i, xored_digest)
        })
        .collect();

    // Check for unique digests
    let mut unique_digests: HashSet<[u8; 32]> = HashSet::with_capacity(num_chunks);
    if indexed_digests
        .iter()
        .any(|(_, digest)| !unique_digests.insert(*digest))
    {
        return Err(InvoluteError::DuplicateCrumbs);
    }

    indexed_digests.par_sort_unstable_by(|a, b| a.1.cmp(&b.1));
    let p: Vec<usize> = indexed_digests.into_iter().map(|(idx, _)| idx).collect();

    let final_perm: Vec<usize> = (0..num_chunks).into_par_iter().map(|i| p[p[i]]).collect();

    let mut result = vec![0u8; packet.len()];
    result
        .par_chunks_mut(chunk_size)
        .enumerate()
        .for_each(|(new_chunk_idx, dest_chunk)| {
            let source_chunk_idx = final_perm[new_chunk_idx];
            let start = source_chunk_idx * chunk_size;
            let end = start + chunk_size;
            dest_chunk.copy_from_slice(&packet[start..end]);
        });
    Ok(result)
}



/// Cycles the private key by using the old key to de-obfuscate the data, followed by a new key to
/// substitute values, then the new key to re-obfuscate the data.
///
/// Both `old_key` and `new_key` must be permutations of the same set of byte values (e.g., 0..256).
///
/// # Arguments
///
/// * `packet` - A byte slice representing the input data to be transformed.
/// * `old_key` - A permutation of unique byte values used for the initial transformation.
/// * `new_key` - A second permutation of the same byte values used for re-substitution.
/// * `chunk_size` - The chunk size to be used in the permutation step.
///
/// # Returns
///
/// A `Result` containing the transformed `Vec<u8>` if successful, or an `InvoluteError` if the
/// transformation fails.
///
/// # Panics
///
/// This function will panic if `old_key` and `new_key` do not contain the same elements (i.e., are
/// not permutations of the same set).
///
/// # Example
/// Demonstrates cycling data from `old_key` to `new_key` and back again:
/// ```
/// use veriphi_core::involute::{cycle_packet, involute_packet, get_chunk_size};
///
/// // Example packet and salts
/// let packet = b"HelloWorld123456"; // len = 16
/// let old_salt = b"old_salt";
/// let new_salt = b"new_salt";
///
/// // Construct trivial permutation keys (identity vs reversed)
/// let old_key: Vec<u8> = (0u8..=255).collect();
/// let mut new_key: Vec<u8> = (0u8..=255).rev().collect();
///
/// // Choose a valid chunk size
/// let chunk_size = get_chunk_size(packet);
///
/// // First, obfuscate the packet with the old salt/key
/// let obfuscated = involute_packet(packet, old_salt, chunk_size).unwrap();
///
/// // Cycle the packet from old_key → new_key
/// let cycled = cycle_packet(&obfuscated, old_salt, new_salt, &old_key, &new_key, chunk_size).unwrap();
///
/// // Cycle back (new_key → old_key), should restore original obfuscation
/// let restored = cycle_packet(&cycled, new_salt, old_salt, &new_key, &old_key, chunk_size).unwrap();
/// assert_eq!(restored, obfuscated);
/// ```
pub fn cycle_packet(
    packet: &[u8],
    old_salt: &[u8],
    new_salt: &[u8],
    old_key: &[u8],
    new_key: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, InvoluteError> {
    let mut sorted_old = old_key.to_vec();
    sorted_old.sort_unstable();
    let mut sorted_new = new_key.to_vec();
    sorted_new.sort_unstable();
    assert_eq!(
        sorted_old, sorted_new,
        "Keys must be permutations from the same set"
    );

    let ciphered_packet = involute_packet(packet, old_salt, chunk_size)?;

    let mut map = vec![0u8; 256]; // assuming u8 values 0-255
    for (i, &old_val) in old_key.iter().enumerate() {
        map[old_val as usize] = new_key[i];
    }
    let swapped_packet: Vec<u8> = ciphered_packet
        .par_iter()
        .map(|&byte| map[byte as usize])
        .collect();

    return Ok(involute_packet(&swapped_packet, new_salt, chunk_size)?);
}


/// Order-Preserving Hasher (OPHasher).
///
/// This struct implements a **simplified order-preserving hashing** scheme:
/// a 32-byte `private_key` seeds an HMAC-SHA256 pseudo-random function (PRF),
/// which recursively splits the input range until a unique output is chosen
/// in the output range. The resulting mapping is:
///
/// - **Deterministic**: same key and input → same output.
/// - **Order-preserving**: if `a < b` then `hash(a) <= hash(b)`.
/// - **Injective within the input range**: each input maps to a distinct output,
///   provided the output range is large enough.
///
/// # Construction
/// Use [`OPHasher::new`] to create an instance:
/// - `key`: secret key material (any length, cloned internally).
/// - `input_min`/`input_max`: inclusive bounds of the valid input domain.
/// - `output_min`/`output_max`: inclusive bounds of the output range.
///   Must be at least as large as the input domain for a fair distribution.
///
/// # Security
/// - This is **not encryption**. It’s a structured PRF that leaks order.
/// - Key secrecy is critical: outputs can be predicted if the key is known.
/// - Use a cryptographically random key (e.g., from `rand::rngs::OsRng`).
///
/// # Example
/// ```
/// use veriphi_core::involute::OPHasher;
///
/// let key = b"super_secret_key_material".to_vec();
/// let oph = OPHasher::new(key, 0, 100, 0, 10_000);
///
/// let h1 = oph.hash(5).unwrap();
/// let h2 = oph.hash(10).unwrap();
///
/// assert!(h1 < h2); // order is preserved
/// ```
pub struct OPHasher {
    private_key: Vec<u8>,
    input_range: (u32, u32),
    output_range: (u64, u64),
}

impl OPHasher {
    /// Constructs a new `OPHasher`.
    ///
    /// # Arguments
    /// - `key`: secret key material (cloned internally).
    /// - `input_min`, `input_max`: inclusive input domain.
    /// - `output_min`, `output_max`: inclusive output range.
    ///
    /// # Panics
    /// - If `input_min > input_max`.
    /// - If `output_min > output_max`.
    /// - If the output range is smaller than the input range.
    pub fn new(
        key: Vec<u8>,
        input_min: u32,
        input_max: u32,
        output_min: u64,
        output_max: u64,
    ) -> Self {
        assert!(input_min <= input_max, "Input min must be <= input max");
        assert!(output_min <= output_max, "Output min must be <= output max");
        assert!(
            (output_max as u128 - output_min as u128 + 1)
                >= (input_max as u128 - input_min as u128 + 1),
            "Output range must be at least as large as input range for good distribution"
        );

        OPHasher {
            private_key: key,
            input_range: (input_min, input_max),
            output_range: (output_min, output_max),
        }
    }

    fn prf(&self, context: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.private_key)
            .expect("HMAC initialised from arbitrary key length");
        mac.update(context);
        return mac.finalize().into_bytes().into();
    }

    fn hash_recursion(
        &self,
        plaintext: u32,
        cur_input_min: u32,
        cur_input_max: u32,
        cur_output_min: u64,
        cur_output_max: u64,
        depth: u32,
    ) -> u64 {
        let cur_input_size = (cur_input_max as u64 - cur_input_min as u64) + 1;
        let cur_output_size = (cur_output_max - cur_output_min) + 1;
        if cur_input_size == 1 {
            return cur_output_min;
        }
        let mut context = Vec::new();
        context.extend_from_slice(&cur_input_min.to_be_bytes());
        context.extend_from_slice(&cur_input_max.to_be_bytes());
        context.extend_from_slice(&cur_output_min.to_be_bytes());
        context.extend_from_slice(&cur_output_max.to_be_bytes());
        context.extend_from_slice(&depth.to_be_bytes());

        let prf_output = self.prf(&context);
        let prf_u64 = u64::from_be_bytes(prf_output[..8].try_into().unwrap());

        let split_ratio = prf_u64 as f64 / u64::MAX as f64;

        let split_idx_in = (cur_input_size as f64 * split_ratio).floor() as u64;
        let split_point_in = cur_input_min as u64 + split_idx_in;

        let split_idx_out = (cur_output_size as f64 * split_ratio).floor() as u64;
        let split_point_out = cur_output_min + split_idx_out;

        if (plaintext as u64) < split_point_in {
            self.hash_recursion(
                plaintext,
                cur_input_min,
                split_point_in as u32 - 1,
                cur_output_min,
                split_point_out - 1,
                depth + 1,
            )
        } else if (plaintext as u64) > split_point_in {
            self.hash_recursion(
                plaintext,
                split_point_in as u32 + 1,
                cur_input_max,
                split_point_out + 1,
                cur_output_max,
                depth + 1,
            )
        } else {
            return split_point_out;
        }
    }

    /// Hashes a value within the input range to a unique, order-preserving output.
    ///
    /// # Arguments
    /// - `plaintext`: input value to hash.
    ///
    /// # Returns
    /// - `Some(output)` if `plaintext` lies within the input range.
    /// - `None` if `plaintext` is out of range.
    ///
    /// # Example
    /// ```
    /// # use veriphi_core::involute::OPHasher;
    /// let oph = OPHasher::new(b"key".to_vec(), 0, 10, 100, 200);
    /// let h = oph.hash(5).unwrap();
    /// assert!(h >= 100 && h <= 200);
    /// ```
    pub fn hash(&self, plaintext: u32) -> Option<u64> {
        if plaintext < self.input_range.0 || plaintext > self.input_range.1 {
            return None;
        }
        Some(self.hash_recursion(
            plaintext,
            self.input_range.0,
            self.input_range.1,
            self.output_range.0,
            self.output_range.1,
            0,
        ))
    }
}

/// Computes a **conditional hash branch** value based on numeric bounds,
/// an input float, and a secret key.
///
/// This function maps the floating `input_value` into an ordered `u32`
/// (via [`float_to_ordered_u32`]) and re-encodes it using an
/// [`OPHasher`] seeded with `key`. The encoded value is compared
/// against `[low_cond, high_cond]` to decide whether the condition passes.
///
/// The returned 64-bit value is then derived as:
/// - `base = (low_cond & high_cond) ^ H(low_cond || high_cond || key)`  
/// - If the condition is true (`low_cond <= enc(input) <= high_cond`),  
///   flip extra bits via XOR with the mask `0xDEADBEEFDEADBEEF`.  
/// - Otherwise, return `base` unchanged.
///
/// # Arguments
/// - `low_cond`: Lower bound of the valid encoded range (inclusive).
/// - `high_cond`: Upper bound of the valid encoded range (inclusive).
/// - `input_value`: Floating-point test value.
/// - `key`: Secret key material used to seed [`OPHasher`] and the SHA-256 hash.
///
/// # Returns
/// A 64-bit branch-dependent value that will differ depending on whether
/// the input lies inside or outside the condition window.
///
/// # Example
/// ```
/// # use veriphi_core::involute::{cond_hash_branch, prep_condition};
/// let key = b"branch-key";
/// let (lo, hi) = prep_condition(-1.0, 1.0, key);
///
/// let inside = cond_hash_branch(lo, hi, 0.0, key);
/// let also_inside = cond_hash_branch(lo, hi, 0.5, key);
/// assert_eq!(inside, also_inside); // consistent for true conditions
///
/// let outside = cond_hash_branch(lo, hi, 10.0, key);
/// assert_ne!(inside, outside); // differs when outside the condition
/// ```
pub fn cond_hash_branch(low_cond: u64, high_cond: u64, input_value: f32, key: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(&low_cond.to_be_bytes());
    hasher.update(&high_cond.to_be_bytes());
    hasher.update(&key);
    let hash = hasher.finalize();
    let c = u64::from_le_bytes(hash[..8].try_into().unwrap());
    let test_int = float_to_ordered_u32(input_value);
    let oph = OPHasher::new(key.to_vec(), 0u32, u32::MAX - 1, 0, u64::MAX - 1);
    let test_enc = oph.hash(test_int).unwrap();
    let cond = (low_cond <= test_enc) && (test_enc <= high_cond);
    let mask = -(cond as i64) as u64;
    let base = (low_cond & high_cond) ^ c;
    return base ^ (mask & 0xDEADBEEFDEADBEEF);
}

/// Prepares embedded condition bounds for use with [`cond_hash_branch`].
///
/// The floating-point `low_bound` and `high_bound` are first mapped into
/// order-preserving integers via [`float_to_ordered_u32`]. These are then
/// embedded into the output domain of an [`OPHasher`] seeded with `salt`.
///
/// This effectively translates real-valued condition ranges into stable,
/// pseudorandomized `u64` bounds that can be compared consistently in
/// the hash-branching logic.
///
/// # Arguments
/// - `low_bound`: Lower bound of the condition window (float).
/// - `high_bound`: Upper bound of the condition window (float).
/// - `salt`: Keying material used to seed the [`OPHasher`].
///
/// # Returns
/// A tuple `(low_embed, high_embed)` of 64-bit values corresponding to
/// the embedded lower and upper bounds in the OPHasher’s output space.
///
/// # Example
/// ```
/// # use veriphi_core::involute::prep_condition;
/// let salt = b"prep-key";
/// let (low, high) = prep_condition(-1.0, 1.0, salt);
///
/// assert!(low < high);
/// // These bounds can now be passed to `cond_hash_branch`
/// ```
pub fn prep_condition(low_bound: f32, high_bound: f32, salt: &[u8]) -> (u64, u64) {
    let low_val = float_to_ordered_u32(low_bound);
    let high_val = float_to_ordered_u32(high_bound);

    let in_min = 0u32;
    let in_max = u32::MAX - 1;
    let out_min = 0u64;
    let out_max = u64::MAX - 1;

    let oph = OPHasher::new(salt.to_vec(), in_min, in_max, out_min, out_max);
    let low_embed = oph.hash(low_val).unwrap();
    let high_embed = oph.hash(high_val).unwrap();
    return (low_embed, high_embed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::gen_key;
    use rand::Rng;

    // -----------------------------
    // Helpers
    // -----------------------------

    fn rand_bytes(len: usize) -> Vec<u8> {
        let mut rng = rand::rng();
        (0..len).map(|_| rng.random()).collect()
    }

    fn is_byte_permutation(a: &[u8], b: &[u8]) -> bool {
        let mut aa = a.to_vec();
        let mut bb = b.to_vec();
        aa.sort_unstable();
        bb.sort_unstable();
        aa == bb
    }

    // -----------------------------
    // involute_packet: basics & errors
    // -----------------------------

    #[test]
    fn involute_returns_empty_on_empty_input() {
        let packet = Vec::<u8>::new();
        let salt = b"salt";
        let out = involute_packet(&packet, salt, 4).expect("empty packet should succeed");
        assert!(out.is_empty());
    }

    #[test]
    fn involute_returns_input_when_chunk_size_is_zero() {
        let packet = vec![1, 2, 3, 4, 5];
        let salt = b"salt";
        let out = involute_packet(&packet, salt, 0).expect("zero chunk size is no-op");
        assert_eq!(out, packet);
    }

    #[test]
    fn involute_rejects_misaligned_chunk_size() {
        let packet = vec![1, 2, 3, 4, 5]; // len = 5
        let salt = b"salt";
        let err = involute_packet(&packet, salt, 4).unwrap_err();
        match err {
            InvoluteError::InvalidPacketSize { packet_len, chunk_size } => {
                assert_eq!(packet_len, 5);
                assert_eq!(chunk_size, 4);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // -----------------------------
    // involute_packet: permutation & involution property
    // -----------------------------

    #[test]
    fn involute_produces_permutation_and_is_reversible_with_same_salt() {
        let original: Vec<u8> = (0u8..=255).collect();
        let salt: &[u8] = &[0, 1, 2, 3, 4];
        let chunk_size = 8;

        let scrambled = involute_packet(&original, salt, chunk_size).expect("permute");
        assert_ne!(scrambled, original, "should not be identity");
        assert!(is_byte_permutation(&scrambled, &original), "must be a permutation");

        let restored = involute_packet(&scrambled, salt, chunk_size).expect("reverse");
        assert_eq!(restored, original, "involution should restore original");
    }

    // -----------------------------
    // cycle_packet: key rotation roundtrip
    // -----------------------------

    #[test]
    fn key_rotation_roundtrip_restores_obfuscation() {
        let original = rand_bytes(320);
        let public_key = gen_key("A", "public_key", &[0; 32]);
        let old_key = gen_key("A", "old_private_key", &[1; 32]);
        let new_key = gen_key("A", "new_private_key", &[2; 32]);
        let chunk_size = get_chunk_size(&original);

        let old_salt = [&old_key[..], &public_key[..]].concat();
        let new_salt = [&new_key[..], &public_key[..]].concat();

        let obfus = involute_packet(&original, &old_salt, chunk_size).expect("obfuscate");
        let cycled =
            cycle_packet(&obfus, &old_salt, &new_salt, &old_key, &new_key, chunk_size).expect("cycle");
        assert_ne!(cycled, original, "cycled data should differ from original");

        let restored =
            cycle_packet(&cycled, &new_salt, &old_salt, &new_key, &old_key, chunk_size).expect("uncycle");
        assert_eq!(restored, obfus, "roundtrip must restore the original obfuscation");
    }

    // -----------------------------
    // cond_involute_packet: conditional permutation behavior
    // -----------------------------

    #[test]
    fn conditional_involute_true_roundtrips_false_does_not() {
        let original = rand_bytes(320);
        let salt = gen_key("A", "private_key", &[0; 32]).to_vec();

        // map float bounds into OPH-embedded bounds
        let low_bound = float_to_ordered_u32(-1.0);
        let high_bound = float_to_ordered_u32(100.0);
        let oph = OPHasher::new(salt.clone(), 0, u32::MAX - 1, 0, u64::MAX - 1);
        let low_embed = oph.hash(low_bound).unwrap();
        let high_embed = oph.hash(high_bound).unwrap();

        // first conditional involute using test value in-range
        let inv_packet =
            cond_involute_packet(&original, &salt, 32, low_embed, high_embed, 0.0).expect("cond inv");

        // in-range test should invert back
        let back_true =
            cond_involute_packet(&inv_packet, &salt, 32, low_embed, high_embed, 99.0).expect("invert true");
        assert_eq!(back_true, original, "in-range condition must restore original");

        // out-of-range test should not invert to original
        let back_false =
            cond_involute_packet(&inv_packet, &salt, 32, low_embed, high_embed, 101.0).expect("invert false");
        assert_ne!(back_false, original, "out-of-range condition must not restore original");
    }

    // -----------------------------
    // get_chunk_size: sanity checks for typical inputs
    // -----------------------------

    #[test]
    fn chunk_size_chooses_smallest_valid_unique_partition() {
        // "abcdefgh" (8 bytes): 4 is the first size >= 4 that yields unique chunks
        let packet = b"abcdefgh";
        let sz = get_chunk_size(packet);
        assert_eq!(sz, 4);

        // "aaaabbbb" (8 bytes): only whole-packet is unique
        let packet = b"aaaaabbbbb";
        let sz = get_chunk_size(packet);
        assert_eq!(sz, 5);

        // empty input
        let empty: &[u8] = &[];
        assert_eq!(get_chunk_size(empty), 0);
    }

    // -----------------------------
    // Determinism smoke check (optional)
    // -----------------------------

    #[test]
    fn involute_is_deterministic_for_fixed_inputs() {
        let data = b"deterministic input data....."; // 29 bytes
        // pad to divisible-by- chunk size
        let padded = {
            let mut v = data.to_vec();
            v.resize(32, 0);
            v
        };
        let salt = b"fixed-salt";
        let chunk = 16;

        let a = involute_packet(&padded, salt, chunk).unwrap();
        let b = involute_packet(&padded, salt, chunk).unwrap();
        assert_eq!(a, b);
    }
}