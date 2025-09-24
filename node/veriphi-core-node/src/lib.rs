use napi::bindgen_prelude::BigInt;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use veriphi_core::{
    utils,
    involute,
    encrypt,
    decrypt,
};


#[napi]
pub fn get_chunk_size(packet: Buffer) -> f64 {
    return involute::get_chunk_size(&packet) as f64;
}

#[napi]
pub fn get_chunk_size_min(packet: Buffer, min_size: f64) -> f64 {
    return involute::get_chunk_size_min(&packet, min_size as usize) as f64;
}

#[napi]
pub fn involute_packet(packet: Buffer, salt: Buffer, chunk_size: f64) -> napi::Result<Buffer> {
    let result = involute::involute_packet(&packet, &salt, chunk_size as usize)
        .map_err(|e| napi::Error::from_reason(format!("Involute error: {}", e)))?;
    return Ok(Buffer::from(result));
}

#[napi]
pub fn cycle_packet(
    packet: Buffer,
    old_salt: Buffer,
    new_salt: Buffer,
    old_key: Buffer,
    new_key: Buffer,
    chunk_size: f64,
) -> napi::Result<Buffer> {
    let cycled = involute::cycle_packet(
        &packet,
        &old_salt,
        &new_salt,
        &old_key,
        &new_key,
        chunk_size as usize,
    )
    .map_err(|e| napi::Error::from_reason(format!("Cycle error: {}", e)))?;
    return Ok(Buffer::from(cycled));
}


#[napi]
pub fn gen_key(party_id: String, purpose: String, master_seed: Buffer) -> napi::Result<Buffer> {
    if master_seed.len() != 32 {
        return Err(napi::Error::from_reason(
            "master_seed must be exactly 32 bytes long".to_string(),
        ));
    }
    let seed_array: &[u8; 32] = master_seed
        .as_ref()
        .try_into()
        .expect("Already checked length");

    let key: [u8; 256] = utils::gen_key(&party_id, &purpose, seed_array);
    return Ok(Buffer::from(&key[..]));
}

#[napi]
pub fn cond_involute_packet(
    packet: Buffer,
    involute_salt: Buffer,
    chunk_size: f64,
    low_bound: BigInt,
    high_bound: BigInt,
    test_value: f64,
) -> napi::Result<Buffer> {
    let involuted = involute::cond_involute_packet(
        &packet,
        &involute_salt,
        chunk_size as usize,
        low_bound.get_u64().1,
        high_bound.get_u64().1,
        test_value as f32,
    )
    .map_err(|e| napi::Error::from_reason(format!("Involute error: {}", e)))?;
    return Ok(Buffer::from(involuted));
}

#[napi]
pub fn cond_hash_branch(
    low_bound: BigInt,
    high_bound: BigInt,
    test_value: f64,
    salt: Buffer,
) -> napi::Result<u64> {
    let condition = involute::cond_hash_branch(
        low_bound.get_u64().1,
        high_bound.get_u64().1,
        test_value as f32,
        &salt,
    );
    return Ok(condition);
}

#[napi]
pub fn prep_condition(low_bound: f64, high_bound: f64, salt: Buffer) -> napi::Result<(u64, u64)> {
    let (low_embed, high_embed) =
        involute::prep_condition(low_bound as f32, high_bound as f32, &salt);
    return Ok((low_embed, high_embed));
}

#[napi]
pub fn map_data(
    pub_key: Buffer,
    priv_key: Buffer,
    identity: f64,
    data_sequence: Vec<Buffer>,
) -> napi::Result<Buffer> {
    let rust_data: Vec<Vec<u8>> = data_sequence.into_iter().map(|b| b.to_vec()).collect();

    let mapped = encrypt::map_data(&pub_key, &priv_key, identity as usize, rust_data);
    return Ok(Buffer::from(mapped));
}

#[napi]
pub fn inv_data(
    pub_key: Buffer,
    priv_keys: Vec<Buffer>,
    data_sequences: Vec<Buffer>,
) -> napi::Result<Vec<Buffer>> {
    let rust_priv: Vec<Vec<u8>> = priv_keys.into_iter().map(|b| b.to_vec()).collect();
    let rust_data: Vec<Vec<u8>> = data_sequences.into_iter().map(|b| b.to_vec()).collect();
    let size = 1 << 8;
    let inv_data = decrypt::inv_data(&pub_key, &rust_priv, rust_data, size as usize);
    let output: Vec<Buffer> = inv_data.into_iter().map(|b| Buffer::from(b)).collect();
    return Ok(output);
}