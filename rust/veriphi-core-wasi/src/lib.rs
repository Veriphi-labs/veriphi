// extern crate wee_alloc;
// use alloc::vec::Vec;
use std::mem::MaybeUninit;
use core::{ptr, slice};
use veriphi_core::{decrypt, encrypt, involute, utils};

// ---------- Error codes ----------

const OK: i32 = 0;
const ERR_BUF_TOO_SMALL: i32 = -1;
const ERR_INVALID_UTF8: i32 = -2;
const ERR_INVALID_SEED: i32 = -3;
const ERR_INTERNAL: i32 = -4;

// ---------- helper funcs ----------
#[inline]
fn read_slice<'a>(ptr_: u32, len: u32) -> &'a [u8] {
    unsafe { slice::from_raw_parts(ptr_ as *const u8, len as usize) }
}

// Read a descriptor table of (ptr,len) pairs, count entries.
pub fn read_slice_table(desc_ptr: u32, count: u32) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(count as usize);
    let mut p = desc_ptr as *const u32;

    unsafe {
        for _ in 0..count {
            let ptr_val = *p;
            p = p.add(1);
            let len_val = *p;
            p = p.add(1);

            out.push(read_slice(ptr_val, len_val).to_vec());
        }
    }
    out
}

// Always write required length (even on ERR_BUF_TOO_SMALL).
fn write_required_len(out_len_ptr: u32, need: usize) {
    unsafe {
        *(out_len_ptr as *mut u32) = need as u32;
    }
}

// Copy into caller buffer (assumes capacity checked by caller or prior path)
fn write_out(out_ptr: u32, data: &[u8]) {
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), out_ptr as *mut u8, data.len());
    }
}

// ---------- Scalar-returning helpers ----------

#[cfg_attr(target_os = "wasi", unsafe(export_name = "getChunkSize"))]
pub extern "C" fn get_chunk_size(packet_ptr: u32, packet_len: u32) -> u32 {
    let packet = read_slice(packet_ptr, packet_len);
    // Note: clamp to u32 (wasm32)
    return involute::get_chunk_size(packet) as u32;
}

#[cfg_attr(target_os = "wasi", unsafe(export_name = "getChunkSizeMin"))]
pub extern "C" fn get_chunk_size_min(packet_ptr: u32, packet_len: u32, min_size: u32) -> u32 {
    let packet = read_slice(packet_ptr, packet_len);
    involute::get_chunk_size_min(packet, min_size as usize) as u32
}

// condHashBranch(low, high, test, salt) -> u64
#[cfg_attr(target_os = "wasi", unsafe(export_name = "condHashBranch"))]
pub extern "C" fn cond_hash_branch(
    low_bound: u64,
    high_bound: u64,
    test_value: f32,
    salt_ptr: u32,
    salt_len: u32,
) -> u64 {
    let salt = read_slice(salt_ptr, salt_len);
    involute::cond_hash_branch(low_bound, high_bound, test_value, salt)
}

// ---------- Byte-returning functions (caller-provided output buffer) ----------

// involutePacket(packet, salt, chunk_size, out_ptr, out_cap, out_len_ptr) -> i32
#[cfg_attr(target_os = "wasi", unsafe(export_name = "involutePacket"))]
pub extern "C" fn involute_packet(
    packet_ptr: u32,
    packet_len: u32,
    salt_ptr: u32,
    salt_len: u32,
    chunk_size: u32,
    out_ptr: u32,
    out_cap: u32,
    out_len_ptr: u32,
) -> i32 {
    let packet = read_slice(packet_ptr, packet_len);
    let salt = read_slice(salt_ptr, salt_len);

    match involute::involute_packet(packet, salt, chunk_size as usize) {
        Ok(buf) => {
            let need = buf.len();
            write_required_len(out_len_ptr, need);
            if need > out_cap as usize {
                return ERR_BUF_TOO_SMALL;
            }
            write_out(out_ptr, &buf);
            OK
        }
        Err(_) => {
            write_required_len(out_len_ptr, 0);
            ERR_INTERNAL
        }
    }
}

// cyclePacket(... many inputs ..., out_ptr, out_cap, out_len_ptr) -> i32
#[cfg_attr(target_os = "wasi", unsafe(export_name = "cyclePacket"))]
pub extern "C" fn cycle_packet(
    packet_ptr: u32,
    packet_len: u32,
    old_salt_ptr: u32,
    old_salt_len: u32,
    new_salt_ptr: u32,
    new_salt_len: u32,
    old_key_ptr: u32,
    old_key_len: u32,
    new_key_ptr: u32,
    new_key_len: u32,
    chunk_size: u32,
    out_ptr: u32,
    out_cap: u32,
    out_len_ptr: u32,
) -> i32 {
    let packet = read_slice(packet_ptr, packet_len);
    let old_salt = read_slice(old_salt_ptr, old_salt_len);
    let new_salt = read_slice(new_salt_ptr, new_salt_len);
    let old_key = read_slice(old_key_ptr, old_key_len);
    let new_key = read_slice(new_key_ptr, new_key_len);

    match involute::cycle_packet(
        packet,
        old_salt,
        new_salt,
        old_key,
        new_key,
        chunk_size as usize,
    ) {
        Ok(buf) => {
            let need = buf.len();
            write_required_len(out_len_ptr, need);
            if need > out_cap as usize {
                return ERR_BUF_TOO_SMALL;
            }
            write_out(out_ptr, &buf);
            OK
        }
        Err(_) => {
            write_required_len(out_len_ptr, 0);
            ERR_INTERNAL
        }
    }
}

// genKey(party_id_utf8, purpose_utf8, master_seed[32], out_ptr, out_cap, out_len_ptr) -> i32
#[cfg_attr(target_os = "wasi", unsafe(export_name = "genKey"))]
pub extern "C" fn gen_key(
    party_ptr: u32,
    party_len: u32,
    purpose_ptr: u32,
    purpose_len: u32,
    master_ptr: u32,
    master_len: u32,
    out_ptr: u32,
    out_cap: u32,
    out_len_ptr: u32,
) -> i32 {
    unsafe {
        let party_bytes = read_slice(party_ptr, party_len);
        let purpose_bytes = read_slice(purpose_ptr, purpose_len);
        if master_len != 32 {
            write_required_len(out_len_ptr, 0);
            return ERR_INVALID_SEED;
        }
        let seed: &[u8; 32] = &*(master_ptr as *const [u8; 32]);

        let party = match core::str::from_utf8(party_bytes) {
            Ok(s) => s,
            Err(_) => {
                write_required_len(out_len_ptr, 0);
                return ERR_INVALID_UTF8;
            }
        };
        let purpose = match core::str::from_utf8(purpose_bytes) {
            Ok(s) => s,
            Err(_) => {
                write_required_len(out_len_ptr, 0);
                return ERR_INVALID_UTF8;
            }
        };

        let key = utils::gen_key(party, purpose, seed).to_vec();
        let need = key.len();
        write_required_len(out_len_ptr, need);
        if need > out_cap as usize {
            return ERR_BUF_TOO_SMALL;
        }
        write_out(out_ptr, &key);
        OK
    }
}

// condInvolutePacket(packet, salt, chunk_size, low, high, test, out..., ...) -> i32
#[cfg_attr(target_os = "wasi", unsafe(export_name = "condInvolutePacket"))]
pub extern "C" fn cond_involute_packet(
    packet_ptr: u32,
    packet_len: u32,
    salt_ptr: u32,
    salt_len: u32,
    chunk_size: u32,
    low_bound: u64,
    high_bound: u64,
    test_value: f32,
    out_ptr: u32,
    out_cap: u32,
    out_len_ptr: u32,
) -> i32 {
    let packet = read_slice(packet_ptr, packet_len);
    let salt = read_slice(salt_ptr, salt_len);

    match involute::cond_involute_packet(
        packet,
        salt,
        chunk_size as usize,
        low_bound,
        high_bound,
        test_value,
    ) {
        Ok(buf) => {
            let need = buf.len();
            write_required_len(out_len_ptr, need);
            if need > out_cap as usize {
                return ERR_BUF_TOO_SMALL;
            }
            write_out(out_ptr, &buf);
            OK
        }
        Err(_) => {
            write_required_len(out_len_ptr, 0);
            ERR_INTERNAL
        }
    }
}

// prepCondition(low, high, salt) -> writes two 128-bit values to `out_ptr`:
// layout: [low_embed(16 bytes little-endian) | high_embed(16 bytes little-endian)]
#[cfg_attr(target_os = "wasi", unsafe(export_name = "prepCondition"))]
pub extern "C" fn prep_condition(
    low_bound: f32,
    high_bound: f32,
    salt_ptr: u32,
    salt_len: u32,
    out_ptr: u32,
    out_cap: u32,
) -> i32 {
    unsafe {
        let salt = read_slice(salt_ptr, salt_len);
        let (low_embed, high_embed) = involute::prep_condition(low_bound, high_bound, salt);

        // Represent as 16-byte little-endian each (u128/i128 both have to_le_bytes()).
        let low_bytes = low_embed.to_le_bytes();
        let high_bytes = high_embed.to_le_bytes();

        let need = 32usize;
        if need > out_cap as usize {
            return ERR_BUF_TOO_SMALL;
        }
        ptr::copy_nonoverlapping(low_bytes.as_ptr(), out_ptr as *mut u8, 16);
        ptr::copy_nonoverlapping(high_bytes.as_ptr(), (out_ptr + 16) as *mut u8, 16);
        OK
    }
}

// mapData(pub_key, priv_key, identity, data_desc_ptr, data_count, out..., ...) -> i32
// `data_desc_ptr` points to `data_count` pairs of (ptr:u32, len:u32).
#[cfg_attr(target_os = "wasi", unsafe(export_name = "mapData"))]
pub extern "C" fn map_data(
    pub_ptr: u32,
    pub_len: u32,
    priv_ptr: u32,
    priv_len: u32,
    identity: u32,
    data_desc_ptr: u32,
    data_count: u32,
    out_ptr: u32,
    out_cap: u32,
    out_len_ptr: u32,
) -> i32 {
    let pub_key = read_slice(pub_ptr, pub_len);
    let priv_key = read_slice(priv_ptr, priv_len);
    let data_vec = read_slice_table(data_desc_ptr, data_count);

    let out = encrypt::map_data(pub_key, priv_key, identity as usize, data_vec);
    let need = out.len();
    write_required_len(out_len_ptr, need);
    if need > out_cap as usize {
        return ERR_BUF_TOO_SMALL;
    }
    write_out(out_ptr, &out);
    OK
}

// invData(pub_key, priv_desc, priv_count, data_desc, data_count, out..., ...) -> i32
// Output encoding: [u32 count][u32 len_0]...[u32 len_{n-1}][bytes_0|bytes_1|...]
#[cfg_attr(target_os = "wasi", unsafe(export_name = "invData"))]
pub extern "C" fn inv_data(
    pub_ptr: u32,
    pub_len: u32,
    priv_desc_ptr: u32,
    priv_count: u32,
    data_desc_ptr: u32,
    data_count: u32,
    out_ptr: u32,
    out_cap: u32,
    out_len_ptr: u32,
) -> i32 {
    unsafe {
        let pub_key = read_slice(pub_ptr, pub_len);
        let priv_vec = read_slice_table(priv_desc_ptr, priv_count);
        let data_vec = read_slice_table(data_desc_ptr, data_count);

        // You had `size = 1 << 8` in JS path; keep same behavior if needed.
        let size = 1usize << 8;
        let outputs = decrypt::inv_data(pub_key, &priv_vec, data_vec, size);

        // Compute total size for encoded buffer
        let count = outputs.len() as u32;
        let header_bytes = 4usize + (count as usize) * 4usize;
        let payload_bytes: usize = outputs.iter().map(|v| v.len()).sum();
        let need = header_bytes + payload_bytes;

        write_required_len(out_len_ptr, need);
        if need > out_cap as usize {
            return ERR_BUF_TOO_SMALL;
        }

        // Write header
        // [count][len_0..len_{n-1}]
        // All little-endian u32.
        let mut p = out_ptr as *mut u8;

        // write count
        *(p as *mut u32) = count;
        p = p.add(4);

        // write lengths
        for v in &outputs {
            *(p as *mut u32) = v.len() as u32;
            p = p.add(4);
        }

        // write payloads
        for v in &outputs {
            ptr::copy_nonoverlapping(v.as_ptr(), p, v.len());
            p = p.add(v.len());
        }

        OK
    }
}

// Memory allocation functions for WebAssembly (WASI).
/// Set the global allocator to the WebAssembly optimized one.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// WebAssembly export that allocates a pointer (linear memory offset) that can
/// be used for a string.
///
/// This is an ownership transfer, which means the caller must call
/// [`deallocate`] when finished.
#[cfg_attr(all(target_os = "wasi"), unsafe(export_name = "allocate"))]
pub extern "C" fn _allocate(size: u32) -> *mut u8 {
    allocate(size as usize)
}

/// Allocates size bytes and leaks the pointer where they start.
fn allocate(size: usize) -> *mut u8 {
    // Allocate the amount of bytes needed.
    let vec: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); size];

    // into_raw leaks the memory to the caller.
    Box::into_raw(vec.into_boxed_slice()) as *mut u8
}


/// WebAssembly export that deallocates a pointer of the given size (linear
/// memory offset, byteCount) allocated by [`allocate`].
#[cfg_attr(all(target_os = "wasi"), unsafe(export_name = "deallocate"))]
pub unsafe extern "C" fn _deallocate(ptr: u32, size: u32) {
    deallocate(ptr as *mut u8, size as usize);
}

/// Retakes the pointer which allows its memory to be freed.
fn deallocate(ptr: *mut u8, size: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}
