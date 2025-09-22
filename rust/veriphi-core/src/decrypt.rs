//! Decryption utilities for recovering original byte streams from
//! split outputs.
//!
//! This module provides two entry points:
//! - [`inv_data`] – stateless inverse (good for high-entropy / few repeats).
//! - [`_inv_data`] – cached inverse using a `DashMap` to deduplicate repeated
//!   rows (good when many rows are identical across sequences).
//!
//! Both rely on precomputed **inverse permutations** of private keys and a
//! shared public key. All keys are expected to be permutations over the same
//! alphabet `0..size-1` (typically `size = 256`).

use dashmap::DashMap;
use rayon::prelude::*;
use std::sync::Arc;

/// Reconstructs a single input tuple (one “row” across all parties) from an
/// output tuple, using the public key and each party’s **inverse** private key.
///
/// The `sequence` slice contains the pooled output value for each party at a
/// given position `i`. For each position, this routine computes the
/// corresponding original inputs using the algebra of the scheme and the
/// synchronized `pub_key`.
///
/// # Requirements
/// - `sequence.len() == inv_keys.len()`
/// - For all `k`: `inv_keys[k].len() == pub_key.len()`
/// - All keys are permutations over `0..size-1`.
///
/// # Arguments
/// - `sequence`: Output tuple across parties for a single index `i`.
/// - `pub_key`: Public permutation (synchronization key).
/// - `inv_keys`: Vector of **inverse** private permutations (one per party).
/// - `size`: Alphabet size (usually `256`).
///
/// # Returns
/// A vector of recovered **original** byte values, one per party.
///
/// # Panics
/// Panics if the length constraints above are not satisfied.
fn backward(sequence: &[u8], pub_key: &[u8], inv_keys: &Vec<Vec<u8>>) -> Vec<u8> {
    assert_eq!(
        sequence.len(),
        inv_keys.len(),
        "There should be there same number of data points as private keys"
    );
    let num_funcs = sequence.len();
    for i in 0..num_funcs {
        assert_eq!(
            pub_key.len(),
            inv_keys[i].len(),
            "All private keys should be the same length as the public key"
        );
    }

    let x_hat_vals: Vec<u8> = sequence
        .iter()
        .zip(inv_keys.iter())
        .map(|(&val, inv)| inv[val as usize])
        .collect();

    let mut x_hat_sum = 0u8;
    let mut x_sum = 0u8;
    for i in 1..(num_funcs - 1) {
        x_hat_sum = x_hat_sum.wrapping_add(x_hat_vals[i]);
    }
    let mut recov_values = vec![0u8; num_funcs];
    if num_funcs > 2 {
        recov_values[num_funcs - 1] = x_hat_vals[num_funcs - 1]
            .wrapping_sub(x_hat_vals[0])
            .wrapping_add(pub_key[x_hat_sum as usize]);
        x_sum = x_sum.wrapping_add(recov_values[num_funcs - 1]);
        for i in (2..=(num_funcs - 2)).rev() {
            x_hat_sum = x_hat_sum.wrapping_sub(x_hat_vals[i]);
            recov_values[i] = x_hat_vals[i]
                .wrapping_sub(x_hat_vals[0])
                .wrapping_add(pub_key[x_hat_sum as usize])
                .wrapping_add(x_sum);
            x_sum = x_sum.wrapping_add(recov_values[i]);
        }
    }
    recov_values[1] = x_hat_vals[1]
        .wrapping_sub(x_hat_vals[0])
        .wrapping_add(x_sum);
    x_sum = x_sum.wrapping_add(recov_values[1]);
    recov_values[0] = x_hat_vals[0].wrapping_add(pub_key[x_sum as usize]);
    return recov_values;
}

/// Inverts a set of output sequences back to their original inputs, with
/// **row-level caching** to exploit repeated tuples.
///
/// This variant builds a `DashMap<Vec<u8>, Arc<Vec<u8>>>` cache keyed by the
/// per-row output tuple (pooled across parties). If many rows are identical
/// (e.g., repeated measurements), cached results avoid recomputation.
/// Work is parallelized across rows.
///
/// Prefer this when your dataset contains **lots of repeated rows**.
///
/// # Arguments
/// - `pub_key`: Public permutation used for synchronization.
/// - `priv_keys`: Private permutations (one per party), all over the same
///   alphabet `0..size-1`.
/// - `data_sequences`: Output sequences (one per party), all of **equal length**.
/// - `size`: Alphabet size (usually `256`).
///
/// # Returns
/// A vector of recovered input sequences, one per party, each having the same
/// length as the inputs.
///
/// # Panics
/// - If `data_sequences.len() != priv_keys.len()`.
/// - If inner sequence lengths differ (`data_sequences[j].len()` mismatch).
/// - If keys are not valid permutations over `0..size-1`.
///
/// # Complexity
/// Let `m = data_sequences.len()` (parties) and `n = length of each sequence`.
/// - Inverting keys: `O(m * size)` (once).
/// - Row processing: `O(n)` *assuming* high cache hit rate; worst case `O(n * m)`
///   calls to the inner reconstruction.
/// - Memory: cache stores unique rows; bounded by number of distinct tuples.
///
/// # Notes
/// - Deterministic for fixed inputs.
/// - Thread-safe: uses `DashMap` + `Arc` to share cached rows across threads.
pub fn inv_data_cached(
    pub_key: &[u8],
    priv_keys: &Vec<Vec<u8>>,
    data_sequences: Vec<Vec<u8>>,
    size: usize,
) -> Vec<Vec<u8>> {
    assert_eq!(
        data_sequences.len(),
        priv_keys.len(),
        "There should be there same number of data sequences as private keys"
    );
    let n = data_sequences[0].len();
    let num_funcs = data_sequences.len();
    for (j, seq) in data_sequences.iter().enumerate() {
        assert!(
            seq.len() == n,
            "all inner vectors must have equal length; \
             data_sequences[0].len() = {}, but data_sequences[{}].len() = {}",
            n,
            j,
            seq.len()
        );
    }

    let inv_keys: Vec<Vec<u8>> = priv_keys
        .par_iter()
        .map(|k| invert_permutation(k, size))
        .collect();

    let cache: Arc<DashMap<Vec<u8>, Arc<Vec<u8>>>> = Arc::new(DashMap::new());

    let rows: Vec<Arc<Vec<u8>>> = (0..n)
        .into_par_iter()
        .map_init(
            || Vec::with_capacity(num_funcs),
            |scratch, i| {
                scratch.clear();
                for col in 0..num_funcs {
                    scratch.push(data_sequences[col][i]);
                }

                // Reuse scratch -> clone it for the key
                let key = scratch.clone();

                // Insert if absent; clone Arc on return (cheap)
                cache
                    .entry(key)
                    .or_insert_with(|| {
                        Arc::new(backward(scratch.as_slice(), pub_key, &inv_keys))
                    })
                    .clone()
            },
        )
        .collect();

    let columns: Vec<Vec<u8>> = (0..num_funcs)
        .into_par_iter()
        .map(|j| {
            let mut col = Vec::with_capacity(n);
            for i in 0..n {
                col.push(rows[i][j]);
            }
            col
        })
        .collect();

    return columns;
}

/// Inverts a set of output sequences back to their original inputs, **without**
/// caching repeated rows.
///
/// This is the simpler, memory-lean variant that processes every row
/// independently. It’s often faster for **high-entropy data** (few repeats),
/// since the cache would not help much.
///
/// # Arguments
/// - `pub_key`: Public permutation used for synchronization.
/// - `priv_keys`: Private permutations (one per party), all over `0..size-1`.
/// - `data_sequences`: Output sequences (one per party), all of **equal length**.
/// - `size`: Alphabet size (usually `256`).
///
/// # Returns
/// A vector of recovered input sequences, one per party.
///
/// # Panics
/// - If `data_sequences.len() != priv_keys.len()`.
/// - If inner sequence lengths differ.
/// - If keys are not valid permutations.
///
/// # Performance
/// Parallelized across rows; no caching overhead. Prefer this version when
/// rows are mostly unique.
pub fn inv_data(
    pub_key: &[u8],
    priv_keys: &Vec<Vec<u8>>,
    data_sequences: Vec<Vec<u8>>,
    size: usize,
) -> Vec<Vec<u8>> {
    assert_eq!(
        data_sequences.len(),
        priv_keys.len(),
        "There should be the same number of data sequences as private keys"
    );
    let n = data_sequences[0].len();
    let num_funcs = data_sequences.len();
    for (j, seq) in data_sequences.iter().enumerate() {
        assert!(
            seq.len() == n,
            "all inner vectors must have equal length; \
             data_sequences[0].len() = {}, but data_sequences[{}].len() = {}",
            n,
            j,
            seq.len()
        );
    }

    let inv_keys: Vec<Vec<u8>> = priv_keys
        .iter()
        .map(|k| invert_permutation(k, size))
        .collect();

    let rows: Vec<Vec<u8>> = (0..n)
        .into_par_iter()
        .map_init(
            || Vec::with_capacity(num_funcs),
            |scratch, i| {
                scratch.clear();
                for col in 0..num_funcs {
                    scratch.push(data_sequences[col][i]);
                }
                backward(scratch.as_slice(), pub_key, &inv_keys)
            },
        )
        .collect();
    let columns: Vec<Vec<u8>> = (0..num_funcs)
        .into_par_iter()
        .map(|j| {
            let mut col = Vec::with_capacity(n);
            for i in 0..n {
                col.push(rows[i][j]);
            }
            col
        })
        .collect();

    return columns;
}

/// Computes the inverse of a byte permutation over `0..size-1`.
///
/// Given a mapping `key[i] = j`, this returns `inv[j] = i`.
///
/// # Arguments
/// - `key`: A permutation over the alphabet `0..size-1`.
/// - `size`: Alphabet size (must be ≥ `key.len()` and consistent with domain).
///
/// # Returns
/// A vector `inv` such that `inv[key[i] as usize] == i as u8`.
///
/// # Panics
/// Panics if `key` is not a valid permutation over `0..size-1` (undefined
/// behavior if duplicate or out-of-range entries are present).
fn invert_permutation(key: &[u8], size: usize) -> Vec<u8> {
    let mut inv = vec![0u8; size];
    for (i, &k) in key.iter().enumerate() {
        inv[k as usize] = i as u8;
    }
    return inv;
}


#[cfg(test)]
mod tests {
    use super::*; // This brings in everything from the parent module
    use rand::Rng;

    fn generate_random_vec(size: usize) -> Vec<u8> {
        let mut rng = rand::rng();
        (0..size).map(|_| rng.random()).collect()
    }

    #[test]
    fn general_inv() {
        use crate::encrypt::map_data;
        use crate::utils::gen_key;
        let size = 1 << 8;
        let num_parties = 6usize;
        let num_data = 500_000;
        let seed = [0u8; 32];
        let pub_key = gen_key(&format!("{:?}", "public"), "gen_key", &seed);
        let data_sets: Vec<Vec<u8>> = (0..num_parties)
            .map(|_| generate_random_vec(num_data))
            .collect();

        let priv_keys: Vec<Vec<u8>> = (0..num_parties)
            .map(|_| {
                // convert whatever gen_key returns into Vec<u8>
                let k = gen_key(&format!("{:?}", "{:i})"), "gen_priv", &seed);
                Vec::from(k) // uses From<[u8;256]> and is identity for Vec<u8>
            })
            .collect();

        let output_data: Vec<Vec<u8>> = (0..num_parties)
            .map(|i| map_data(&pub_key, &priv_keys[i], i as usize, data_sets.clone()))
            .collect();

        let results = inv_data(&pub_key, &priv_keys, output_data, size);

        for i in 0..num_parties {
            assert_eq!(results[i as usize], data_sets[i as usize]);
        }
    }
    #[test]
    fn general_cache_inv() {
        use crate::encrypt::map_data;
        use crate::utils::gen_key;
        let size = 1 << 8;
        let num_parties = 6usize;
        let num_data = 500_000;
        let seed = [0u8; 32];
        let pub_key = gen_key(&format!("{:?}", "public"), "gen_key", &seed);
        let data_sets: Vec<Vec<u8>> = (0..num_parties)
            .map(|_| generate_random_vec(num_data))
            .collect();

        let priv_keys: Vec<Vec<u8>> = (0..num_parties)
            .map(|_| {
                // convert whatever gen_key returns into Vec<u8>
                let k = gen_key(&format!("{:?}", "{:i})"), "gen_priv", &seed);
                Vec::from(k) // uses From<[u8;256]> and is identity for Vec<u8>
            })
            .collect();

        let output_data: Vec<Vec<u8>> = (0..num_parties)
            .map(|i| map_data(&pub_key, &priv_keys[i], i as usize, data_sets.clone()))
            .collect();

        let results = inv_data_cached(&pub_key, &priv_keys, output_data, size);

        for i in 0..num_parties {
            assert_eq!(results[i as usize], data_sets[i as usize]);
        }
    }
}
