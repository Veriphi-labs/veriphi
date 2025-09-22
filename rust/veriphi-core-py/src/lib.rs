use numpy::PyReadonlyArray1;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use pyo3::{PyErr, PyObject, PyResult, Python};

// custom imports
use veriphi_core::utils;
use veriphi_core::involute;
use veriphi_core::encrypt;
use veriphi_core::decrypt;

#[pyfunction]
pub fn get_chunk_size(_py: Python<'_>, packet: PyReadonlyArray1<u8>) -> PyResult<usize> {
    let packet_slice = packet.as_slice()?;
    let chunk_size = involute::get_chunk_size(packet_slice);
    return Ok(chunk_size);
}

#[pyfunction]
pub fn get_chunk_size_min(
    _py: Python<'_>,
    packet: PyReadonlyArray1<u8>,
    min_size: usize,
) -> PyResult<usize> {
    let packet_slice = packet.as_slice()?;
    let chunk_size = involute::get_chunk_size_min(packet_slice, min_size);
    return Ok(chunk_size);
}

#[pyfunction]
pub fn involute_packet(
    py: Python<'_>,
    packet: PyReadonlyArray1<u8>,
    salt: PyReadonlyArray1<u8>,
    chunk_size: usize,
) -> PyResult<PyObject> {
    let packet_slice = packet.as_slice()?;
    let salt_slice = salt.as_slice()?;
    let involuted =
        involute::involute_packet(packet_slice, salt_slice, chunk_size).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Involute error: {}", e))
        })?;
    let involuted_bytes = PyBytes::new(py, &involuted);

    return Ok(involuted_bytes.into());
}

#[pyfunction]
pub fn cycle_packet(
    py: Python<'_>,
    packet: PyReadonlyArray1<u8>,
    old_salt: PyReadonlyArray1<u8>,
    new_salt: PyReadonlyArray1<u8>,
    old_key: PyReadonlyArray1<u8>,
    new_key: PyReadonlyArray1<u8>,
    chunk_size: usize,
) -> PyResult<PyObject> {
    let packet_slice = packet.as_slice()?;
    let old_salt_slice = old_salt.as_slice()?;
    let new_salt_slice = new_salt.as_slice()?;
    let old_key_slice = old_key.as_slice()?;
    let new_key_slice = new_key.as_slice()?;
    let cycled = involute::cycle_packet(
        &packet_slice,
        &old_salt_slice,
        &new_salt_slice,
        &old_key_slice,
        &new_key_slice,
        chunk_size,
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Cycle error: {}", e)))?;
    let cycled_bytes = PyBytes::new(py, &cycled);
    return Ok(cycled_bytes.into());
}

#[pyfunction]
pub fn gen_key(
    py: Python<'_>,
    party_id: &str,
    purpose: &str,
    master_seed: PyReadonlyArray1<u8>,
) -> PyResult<PyObject> {
    let seed_slice = master_seed.as_slice().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Seed array not contiguous: {}", e))
    })?;
    if seed_slice.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "master_seed must be exactly 32 bytes long",
        ));
    }

    // Convert slice to fixed-size array
    let seed_array: &[u8; 32] = seed_slice
        .try_into()
        .expect("Checked length; this should never panic");
    let key = utils::gen_key(party_id, purpose, seed_array);
    let py_bytes = PyBytes::new(py, &key);
    return Ok(py_bytes.into());
}

#[pyfunction]
pub fn cond_involute_packet(
    py: Python<'_>,
    packet: PyReadonlyArray1<u8>,
    involute_salt: PyReadonlyArray1<u8>,
    chunk_size: usize,
    low_bound: u64,
    high_bound: u64,
    test_value: f32,
) -> PyResult<PyObject> {
    let packet_slice = packet.as_slice()?;
    let involute_salt_slice = involute_salt.as_slice()?;
    let involuted = involute::cond_involute_packet(
        packet_slice,
        involute_salt_slice,
        chunk_size,
        low_bound,
        high_bound,
        test_value,
    )
    .map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Involute error: {}", e))
    })?;
    let involuted_bytes = PyBytes::new(py, &involuted);
    return Ok(involuted_bytes.into());
}

#[pyfunction]
pub fn cond_hash_branch(
    _py: Python<'_>,
    low_bound: u64,
    high_bound: u64,
    test_value: f32,
    salt: PyReadonlyArray1<u8>,
) -> PyResult<u64> {
    let salt_slice = salt.as_slice()?;
    let condition = involute::cond_hash_branch(low_bound, high_bound, test_value, salt_slice);
    return Ok(condition);
}

#[pyfunction]
pub fn prep_condition(
    _py: Python<'_>,
    low_bound: f32,
    high_bound: f32,
    salt: PyReadonlyArray1<u8>,
) -> PyResult<(u64, u64)> {
    let salt_slice = salt.as_slice()?;
    let (low_embed, high_embed) = involute::prep_condition(low_bound, high_bound, &salt_slice);
    return Ok((low_embed, high_embed));
}

#[pyfunction]
pub fn map_data(
    py: Python<'_>,
    pub_key: PyReadonlyArray1<u8>,
    priv_key: PyReadonlyArray1<u8>,
    identity: usize,
    data_sequences: Vec<PyReadonlyArray1<u8>>,
) -> PyResult<PyObject> {
    let pub_slice = pub_key.as_slice()?;
    let priv_slice = priv_key.as_slice()?;

    let rust_data: Vec<Vec<u8>> = data_sequences
        .into_iter()
        .map(|arr| arr.as_slice().unwrap().to_vec())
        .collect();

    // Call your existing Rust function
    let output_vec = encrypt::map_data(pub_slice, priv_slice, identity, rust_data);
    let output_bytes = PyBytes::new(py, &output_vec);
    Ok(output_bytes.into())
}

#[pyfunction]
pub fn inv_data(
    py: Python<'_>,
    pub_key: PyReadonlyArray1<u8>,
    priv_keys: Vec<PyReadonlyArray1<u8>>,
    data_sequences: Vec<PyReadonlyArray1<u8>>,
) -> PyResult<PyObject> {
    let pub_slice = pub_key.as_slice()?;
    let priv_slice = priv_keys
        .into_iter()
        .map(|arr| arr.as_slice().unwrap().to_vec())
        .collect::<Vec<Vec<u8>>>();
    let data_slice = data_sequences
        .into_iter()
        .map(|arr| arr.as_slice().unwrap().to_vec())
        .collect();

    let size = 1 << 8;
    let output_vec = decrypt::inv_data(pub_slice, &priv_slice, data_slice, size as usize);
    let output_list = PyList::new(py, output_vec.iter().map(|row| PyBytes::new(py, &row)))?;

    Ok(output_list.into())
}

/// Create the Python module
#[pymodule]
pub fn veriphi_core_py(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(involute_packet, py)?)?;
    m.add_function(wrap_pyfunction!(cycle_packet, py)?)?;
    m.add_function(wrap_pyfunction!(get_chunk_size, py)?)?;
    m.add_function(wrap_pyfunction!(get_chunk_size_min, py)?)?;
    m.add_function(wrap_pyfunction!(cond_involute_packet, py)?)?;
    m.add_function(wrap_pyfunction!(gen_key, py)?)?;
    m.add_function(wrap_pyfunction!(prep_condition, py)?)?;
    m.add_function(wrap_pyfunction!(cond_hash_branch, py)?)?;
    m.add_function(wrap_pyfunction!(map_data, py)?)?;
    m.add_function(wrap_pyfunction!(inv_data, py)?)?;
    Ok(())
}