//! Mapping functions for forward transformation of pooled data sequences.
//!
//! This module implements the *forward direction* of the scheme, where
//! each party’s private key and a shared public key are used to map
//! pooled data values into a new output stream.  
//!
//! # Overview
//! - [`map_data`] is the main public entry point: it takes all parties’
//!   data sequences, plus this party’s private key and index, and
//!   produces this party’s mapped output in parallel.
//! - Internally, [`forward`] handles the row-level transformation for
//!   a single identity given the pooled row values.
//! - [`reverse_cumsum`] is a helper for computing suffix sums needed
//!   in the mapping algebra.
//!
//! # Data layout
//! - Input: `data_sequences` is a vector of per-party columns
//!   (`Vec<Vec<u8>>`), all the same length.
//! - On each row `i`, the values from all parties form a tuple
//!   `[v0[i], v1[i], …, v_{m-1}[i]]`.
//! - [`map_data`] processes each row in parallel and yields a `Vec<u8>`
//!   containing this party’s mapped output stream.
//!
//! # Guarantees
//! - Panics if fewer than 2 parties are provided.
//! - Panics if `identity` is out of range or if input sequences differ
//!   in length.
//!
//! # See also
//! - The inverse mapping utilities in the corresponding `inv_data` module.

use rayon::prelude::*;

/// Computes the mapped value for a single party at a single position,
/// given the pooled output tuple across all parties.
///
/// Conceptually, this takes one “row” (the `sequence` = `[v0[i], v1[i], …]`)
/// and applies the scheme’s algebra to recover the intermediate values
/// (`x_hat_*`) using the shared `pub_key`, then selects the result for
/// `identity` and maps it through that party’s `priv_key`.
///
/// This is an internal helper; the public entry point is [`map_data`].
///
/// # Arguments
/// - `sequence`: The i-th pooled tuple across all parties (`len = num_funcs`).
/// - `pub_key`: Public permutation that synchronizes all parties.
/// - `priv_key`: The calling party’s private permutation.
/// - `identity`: Index of the calling party in `[0, num_funcs)`.
///
/// # Returns
/// The mapped byte for the calling party at this position.
///
/// # Panics
/// - If `identity >= sequence.len()`.
/// - If indices derived during computation exceed the bounds of `pub_key`
///   or `priv_key` (should not occur if keys are valid permutations over
///   the same alphabet).
///
#[inline] fn forward(sequence: &[u8], pub_key: &[u8], priv_key: &[u8], identity: usize) -> u8 {
    let num_funcs = sequence.len();
    assert!(identity < num_funcs);
    let final_sum = reverse_cumsum(sequence);
    let x_hat_0 = sequence[0].wrapping_sub(pub_key[final_sum[1] as usize]);
    if identity == 0 {
        return priv_key[x_hat_0 as usize];
    }
    let x_hat_1 = x_hat_0.wrapping_add(sequence[1]).wrapping_sub(final_sum[2]);
    if identity == 1 {
        return priv_key[x_hat_1 as usize];
    }
    let mut prefix_sum = x_hat_1;
    let mut x_hat_curr = x_hat_1;
    for i in 1..identity {
        x_hat_curr = x_hat_0
            .wrapping_sub(pub_key[prefix_sum as usize])
            .wrapping_add(sequence[i + 1])
            .wrapping_sub(final_sum[i + 2]);
        prefix_sum = prefix_sum.wrapping_add(x_hat_curr);
    }
    return priv_key[x_hat_curr as usize];
}

/// Maps **pooled data sequences** into this party’s output stream, in parallel.
///
/// You pass in:
/// - the shared `pub_key`,
/// - *this party’s* `priv_key`,
/// - your `identity` (index among all parties),
/// - and the **pooled** data for all parties (`data_sequences`), where each
///   inner vector is that party’s column of values.
///   
/// The function assembles each row `i` as a tuple `[v0[i], v1[i], …, v_{m-1}[i]]`
/// and applies the mapping algebra (via a private [`forward`] call) to produce
/// one output byte for this party. Rows are processed with Rayon in parallel.
///
/// # Arguments
/// - `pub_key`: Public permutation (synchronization key).
/// - `priv_key`: This party’s private permutation.
/// - `identity`: Index of this party in `[0, m)`, where `m = data_sequences.len()`.
/// - `data_sequences`: One `Vec<u8>` per party; **all must have equal length**.
///
/// # Returns
/// A `Vec<u8>` with the mapped output for this party; its length matches the
/// inner vectors of `data_sequences`.
///
/// # Panics
/// - If `data_sequences.len() < 2`.
/// - If `identity >= data_sequences.len()`.
/// - If any inner vector length differs from the first (non-rectangular input).
///
/// # Performance
/// - Work is parallelized over rows using Rayon.
/// - Per row, the cost is dominated by the internal [`forward`] computation,
///   which is `O(identity)` for the party at index `identity`.
pub fn map_data(
    pub_key: &[u8],
    priv_key: &[u8],
    identity: usize,
    data_sequences: Vec<Vec<u8>>,
) -> Vec<u8> {
    let num_funcs = data_sequences.len();
    // some data checks
    assert!(num_funcs > 1, "At least two parties must be present");
    assert!(identity < num_funcs);
    let n = data_sequences[0].len();
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
    // now onto computation
    let output = (0..n)
        .into_par_iter()
        .map_init(
            || Vec::with_capacity(num_funcs),
            |scratch, i| {
                scratch.clear();
                // Build the i-th column as a row/sequence: [v0[i], v1[i], ..., v_{m-1}[i]]
                for col in 0..num_funcs {
                    // Safe: we asserted rectangular shape above
                    scratch.push(data_sequences[col][i]);
                }
                // Call your existing forward on the assembled sequence
                forward(scratch.as_slice(), pub_key, priv_key, identity)
            },
        )
        .collect();
    return output;
}

/// Computes a **reverse cumulative sum** of an input slice with `u8` wrapping.
///
/// For input `[a0, a1, …, a_{n-1}]`, this returns a vector of length `n + 1`:
/// `[sum(a0..a_{n-1}), sum(a1..a_{n-1}), …, sum(a_{n-1}), 0]`,
/// where addition uses `u8::wrapping_add`.
///
/// This helper is used by the mapping algebra to obtain suffix sums.
/// The final element is always `0`.
///
/// # Arguments
/// - `input`: Slice of bytes to cumulatively sum from the end.
///
/// # Returns
/// A `Vec<u8>` of length `input.len() + 1` containing the reverse sums.
///
/// # Notes
/// - Sums are modulo-256 (`wrapping_add`).
/// - The last element is a sentinel `0`.
#[inline] fn reverse_cumsum(input: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; input.len() + 1];
    let mut running_sum = 0u8;
    for (i, &val) in input.iter().enumerate().rev() {
        running_sum = running_sum.wrapping_add(val);
        output[i] = running_sum;
    }
    output[input.len()] = 0u8;
    return output;
}


#[cfg(test)]
mod tests {
    use super::*; // This brings in everything from the parent module
    /// Tests for mapping functions ///

    fn _gen_a() -> Vec<u8> {
        (0u8..=255).collect()
    }
    fn _rot_a() -> Vec<u8> {
        _gen_a().iter().map(|x| x.wrapping_add(10)).collect()
    }
    fn _gen_b() -> Vec<u8> {
        _rot_a().iter().map(|x| x.wrapping_add(128)).collect()
    }
    fn _gen_c() -> Vec<u8> {
        _gen_b().iter().map(|x| x.wrapping_add(10)).collect()
    }
    fn _rot_c() -> Vec<u8> {
        _rot_a().iter().map(|x| x.wrapping_add(64)).collect()
    }
    fn _gen_d() -> Vec<u8> {
        _gen_c().iter().map(|x| x.wrapping_add(10)).collect()
    }

    fn test_vals() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let a_vals: Vec<u8> = (0u8..=9).collect();
        let b_vals: Vec<u8> = a_vals.iter().map(|x| x.wrapping_add(10)).collect();
        let c_vals: Vec<u8> = b_vals.iter().map(|x| x.wrapping_add(20)).collect();
        (a_vals, b_vals, c_vals)
    }

    fn test_vals4() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let a_vals: Vec<u8> = (0u8..=9).collect();
        let b_vals: Vec<u8> = a_vals.iter().map(|x| x.wrapping_add(10)).collect();
        let c_vals: Vec<u8> = b_vals.iter().map(|x| x.wrapping_add(20)).collect();
        let d_vals: Vec<u8> = c_vals.iter().map(|x| x.wrapping_add(10)).collect();
        (a_vals, b_vals, c_vals, d_vals)
    }

    #[test]
    fn test_3way() {
        let priv_a = _gen_a();
        let priv_b = _gen_b();
        let priv_c = _gen_c();
        let pub_key = _rot_a();
        let (a_vals, b_vals, c_vals) = test_vals();
        let pooled_vals = vec![a_vals.clone(), b_vals.clone(), c_vals.clone()];
        let a_map = map_data(&pub_key, &priv_a, 0usize, pooled_vals.clone());
        let b_map = map_data(&pub_key, &priv_b, 1usize, pooled_vals.clone());
        let c_map = map_data(&pub_key, &priv_c, 2usize, pooled_vals.clone());
        let expected_a: Vec<u8> = (197..=206).rev().collect();
        assert_eq!(
            a_map, expected_a,
            "map_a did not produce the expected result"
        );
        let expected_b: Vec<u8> = (59..=68).rev().collect();
        assert_eq!(
            b_map, expected_b,
            "map_b did not produce the expected result"
        );
        let expected_c: Vec<u8> = (188..=197).collect();
        assert_eq!(
            c_map, expected_c,
            "map_c did not produce the expected result"
        );
    }
    
    #[test]
    fn test_4way() {
        let priv_a = _gen_a();
        let priv_b = _gen_b();
        let priv_c = _gen_c();
        let priv_d = _gen_d();
        let pub_key = _rot_a();

        let (a_vals, b_vals, c_vals, d_vals) = test_vals4();
        let pooled_vals = vec![
            a_vals.clone(),
            b_vals.clone(),
            c_vals.clone(),
            d_vals.clone(),
        ];
        let a_map = map_data(&pub_key, &priv_a, 0usize, pooled_vals.clone());
        let b_map = map_data(&pub_key, &priv_b, 1usize, pooled_vals.clone());
        let c_map = map_data(&pub_key, &priv_c, 2usize, pooled_vals.clone());
        let d_map = map_data(&pub_key, &priv_d, 3usize, pooled_vals.clone());
        let expected_a: Vec<u8> = (148..=166).rev().step_by(2).collect();
        assert_eq!(
            a_map, expected_a,
            "map_a did not produce the expected result"
        );
        let expected_b: Vec<u8> = (217..=244).rev().step_by(3).collect();
        assert_eq!(
            b_map, expected_b,
            "map_b did not produce the expected result"
        );
        let expected_c: Vec<u8> = (188..=197).collect();
        assert_eq!(
            c_map, expected_c,
            "map_c did not produce the expected result"
        );
        let expected_d: Vec<u8> = (208..=217).collect();
        assert_eq!(
            d_map, expected_d,
            "map_d did not produce the expected result"
        );
    }
}
