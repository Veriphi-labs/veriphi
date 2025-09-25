use veriphi_core as vc;

#[forbid(unsafe_code)]

use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use getrandom;
use aes::Aes256;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use ctr::cipher::{KeyIvInit, StreamCipher};
use std::ops::{Deref, DerefMut};


use vc::{encrypt, decrypt, involute, utils};


#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid seed length: expected 32 bytes")]
    BadSeed,
    #[error("invalid mode string; expected 2 chars like E2/K3")]
    BadMode,
    #[error("all streams must have equal length")]
    UnequalStreams,
    #[error("identities must be 0..num_parties-1 and unique")]
    BadIdentities,
    #[error("modes or public keys do not match across packets")]
    Mismatch,
    #[error("aes gcm failure")]
    AesGcm,
    #[error("bad nonce length: expected {expected} bytes, got {got}")]
    BadNonceLen { expected: usize, got: usize },
    #[error("input too short or malformed while parsing bytes")]
    Truncated,
    #[error("invalid declared length while parsing bytes")]
    BadLength,
    #[error("failed to decode UTF-8 string in packet")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("unexpected end of input while reading bytes")]
    UnexpectedEof,
    #[error("integer overflow while computing offset/length")]
    Overflow,
    #[error("deobfuscated payload missing (did you call recover_packets?)")]
    MissingDeobf,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Check key has all unique values
fn check_key_bytes(key: &[u8]) -> Result<()> {
    use std::collections::HashSet;
    let set: HashSet<u8> = key.iter().copied().collect();
    if set.len() != key.len() {
        return Err(Error::Mismatch);
    }
    Ok(())
}

/// PBKDF2-SHA256 to derive a 32-byte key
pub fn derive_encryption_key(private_key: &[u8], count: u32, context: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(private_key, context, count, &mut out);
    out
}

const DEFAULT_PBKDF2_ITERS: u32 = 250_000;

pub fn encrypt_aes_ctr(private_key: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 8]) {
    encrypt_aes_ctr_with_iters(private_key, plaintext, DEFAULT_PBKDF2_ITERS)
}

pub fn encrypt_aes_ctr_with_iters(
    private_key: &[u8],
    plaintext: &[u8],
    num_iter: u32,
) -> (Vec<u8>, [u8; 8]) {
    // Derive key
    let key = derive_encryption_key(private_key, num_iter, b"setup_encryption");

    // 8-byte nonce -> placed in the high 8 bytes of a 16-byte IV (Ctr64BE)
    let mut nonce8 = [0u8; 8];
    getrandom::fill(&mut nonce8).expect("OS RNG failed");

    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&nonce8);

    // 64-bit big-endian counter CTR
    type Ctr64 = ctr::Ctr64BE<Aes256>;
    let mut cipher = Ctr64::new((&key).into(), (&iv).into());

    let mut buf = plaintext.to_vec();
    cipher.apply_keystream(&mut buf);
    (buf, nonce8)
}


pub fn _encrypt_aes_ctr_with_nonce(
    private_key: &[u8],
    plaintext: &[u8],
    nonce8: &[u8],
) -> Result<Vec<u8>> {
    if nonce8.len() != 8 {
        return Err(Error::BadNonceLen { expected: 8, got: nonce8.len() });
    }

    // Derive the 256-bit AES key (same params as the random-nonce variant).
    let key = derive_encryption_key(private_key, DEFAULT_PBKDF2_ITERS, b"setup_encryption");

    // Build 16-byte IV with the 8-byte nonce in the high half.
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(nonce8);

    // AES-256 CTR with 64-bit big-endian counter.
    type Ctr64 = ctr::Ctr64BE<aes::Aes256>;
    let mut cipher = Ctr64::new((&key).into(), (&iv).into());

    let mut buf = plaintext.to_vec();
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

pub fn decrypt_aes_ctr(private_key: &[u8], nonce8: &[u8; 8], ciphertext: &[u8]) -> Vec<u8> {
    decrypt_aes_ctr_with_iters(private_key, nonce8, ciphertext, DEFAULT_PBKDF2_ITERS)
}

pub fn decrypt_aes_ctr_with_iters(
    private_key: &[u8],
    nonce8: &[u8; 8],
    ciphertext: &[u8],
    num_iter: u32,
) -> Vec<u8> {
    let key = derive_encryption_key(private_key, num_iter, b"setup_encryption");

    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(nonce8);

    type Ctr64 = ctr::Ctr64BE<Aes256>;
    let mut cipher = Ctr64::new((&key).into(), (&iv).into());

    let mut buf = ciphertext.to_vec();
    cipher.apply_keystream(&mut buf);
    buf
}

// -------------------- AES-GCM --------------------

pub fn encrypt_aes_gcm(private_key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 16], [u8; 12])> {
    encrypt_aes_gcm_with_iters(private_key, plaintext, DEFAULT_PBKDF2_ITERS)
}

/// AES-GCM with 12-byte nonce; returns (ciphertext, tag, nonce)
pub fn encrypt_aes_gcm_with_iters(
    private_key: &[u8],
    plaintext: &[u8],
    num_iter: u32,
) -> Result<(Vec<u8>, [u8; 16], [u8; 12])> {
    let key = derive_encryption_key(private_key, num_iter, b"setup_encryption");
    let cipher = Aes256Gcm::new((&key).into());

    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("OS RNG failed");
    let nonce_gcm = Nonce::from_slice(&nonce);

    // Aes256Gcm::encrypt returns ct||tag, tag is 16 bytes
    let ciphertext_with_tag = cipher.encrypt(nonce_gcm, plaintext)
        .expect("gcm encrypt");

    let tag_len = 16;
    let ct_len = ciphertext_with_tag.len().saturating_sub(tag_len);
    let (ct, tag) = ciphertext_with_tag.split_at(ct_len);

    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(tag);

    Ok((ct.to_vec(), tag_arr, nonce))
}

pub fn decrypt_aes_gcm(
    private_key: &[u8],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    decrypt_aes_gcm_with_iters(private_key, nonce, ciphertext, tag, DEFAULT_PBKDF2_ITERS)
}

pub fn decrypt_aes_gcm_with_iters(
    private_key: &[u8],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
    num_iter: u32,
) -> Result<Vec<u8>> {
    let key = derive_encryption_key(private_key, num_iter, b"setup_encryption");
    let cipher = Aes256Gcm::new((&key).into());
    let nonce_gcm = Nonce::from_slice(nonce);

    // Recreate ct||tag as expected by the `decrypt` API
    let mut ct_tag = Vec::with_capacity(ciphertext.len() + 16);
    ct_tag.extend_from_slice(ciphertext);
    ct_tag.extend_from_slice(tag);

    cipher.decrypt(nonce_gcm, ct_tag.as_ref())
        .map_err(|_| Error::AesGcm)
}

/// Stream data into `E#` or `K#` streams (Uint8 semantics)
fn stream_data(mode: &str, data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if mode.len() != 2 {
        return Err(Error::BadMode);
    }
    let letter = mode.chars().next().unwrap().to_ascii_uppercase();
    let num_streams: usize = mode[1..2].parse().map_err(|_| Error::BadMode)?;
    let remainder = (num_streams - (data.len() % num_streams)) % num_streams;

    let mut mod_data = Vec::with_capacity(data.len() + remainder);
    mod_data.extend_from_slice(data);
    if remainder > 0 {
        mod_data.resize(mod_data.len() + remainder, 0);
    }

    match letter {
        'E' => s_eq_data(num_streams, &mod_data),
        'K' => s_kip_data(num_streams, &mod_data),
        _ => Err(Error::BadMode),
    }
}

fn s_eq_data(num_streams: usize, data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let stream_len = data.len() / num_streams;
    let mut out = Vec::with_capacity(num_streams);
    for i in 0..num_streams {
        out.push(data[i * stream_len..(i + 1) * stream_len].to_vec());
    }
    Ok(out)
}

fn s_kip_data(num_streams: usize, data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let stream_len = data.len() / num_streams;
    let mut out = vec![vec![0u8; stream_len]; num_streams];
    for i in 0..num_streams {
        for j in 0..stream_len {
            out[i][j] = data[i + j * num_streams];
        }
    }
    Ok(out)
}

fn recombine_data(mode: &str, streams: &[Vec<u8>]) -> Result<Vec<u8>> {
    if mode.len() != 2 {
        return Err(Error::BadMode);
    }
    let letter = mode.chars().next().unwrap().to_ascii_uppercase();
    let num_streams: usize = mode[1..2].parse().map_err(|_| Error::BadMode)?;
    if num_streams != streams.len() {
        return Err(Error::BadMode);
    }
    let len0 = streams[0].len();
    if streams.iter().any(|s| s.len() != len0) {
        return Err(Error::UnequalStreams);
    }

    let stacked: Vec<u8> = streams.iter().flat_map(|s| s.iter().copied()).collect();

    match letter {
        'E' => r_eq_data(num_streams, &stacked),
        'K' => r_kip_data(num_streams, &stacked),
        _ => Err(Error::BadMode),
    }
}

fn r_eq_data(num_streams: usize, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % num_streams != 0 {
        return Err(Error::UnequalStreams);
    }
    Ok(data.to_vec())
}

fn r_kip_data(num_streams: usize, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % num_streams != 0 {
        return Err(Error::UnequalStreams);
    }
    let stream_len = data.len() / num_streams;
    let mut out = vec![0u8; data.len()];
    for i in 0..stream_len {
        for j in 0..num_streams {
            out[i * num_streams + j] = data[j * stream_len + i];
        }
    }
    Ok(out)
}

/// Helpers for LE u64 packing
fn pack_u64_le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}
fn read_u64_le(buf: &[u8], off: &mut usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[*off..*off + 8]);
    *off += 8;
    u64::from_le_bytes(a)
}

pub struct Utils {
    pub party_id: String,
}

impl Utils {
    pub fn new(party_id: impl Into<String>) -> Self {
        Self { party_id: party_id.into() }
    }

    pub fn gen_private_key(&self, purpose: &str, seed: &[u8]) -> Result<Vec<u8>> {
        if seed.len() != 32 {
            return Err(Error::BadSeed);
        }
        let seed32: &[u8; 32] = seed.try_into().unwrap();
        let k = utils::gen_key(&self.party_id, purpose, seed32);
        check_key_bytes(&k)?;
        Ok(k.to_vec())
    }

    pub fn check_key(&self, key: &[u8]) -> Result<()> {
        check_key_bytes(key)
    }
}

pub struct SetupNode(Utils);
impl SetupNode {
    pub fn new(party_id: impl Into<String>) -> Self {
        Self(Utils::new(party_id))
    }

    pub fn gen_public_key(&self, seed: &[u8]) -> Result<Vec<u8>> {
        let k = self.0.gen_private_key("publicKey", seed)?;
        self.0.check_key(&k)?;
        Ok(k)
    }

    pub fn implement_conditions(&self, low: f32, high: f32, private_key: &[u8]) -> Result<(u64, u64)> {
        let (lo, hi) = involute::prep_condition(low, high, private_key);
        Ok((lo, hi))
    }

    pub fn _test_conditions(&self, low: f32, high: f32, test: f32, private_key: &[u8]) -> Result<u64> {
        let (lo, hi) = involute::prep_condition(low, high, private_key);
        Ok(involute::cond_hash_branch(lo, hi, test, private_key))
    }

    pub fn obfuscate_data(
        &self,
        packet: &[u8],
        private_key: &[u8],
        low: u64,
        high: u64,
        test: f32,
    ) -> Result<(Vec<u8>, usize)> {
        let chunk = involute::get_chunk_size(packet);
        let inv = involute::cond_involute_packet(packet, private_key, chunk, low, high, test)
            .map_err(|_| Error::Mismatch)?;
        Ok((inv, chunk))
    }

    pub fn encrypt_data(&self, data: &[u8], private_key: &[u8]) -> (Vec<u8>, [u8; 8]) {
        encrypt_aes_ctr(private_key, data)
    }

    pub fn _encrypt_data_gcm(&self, data: &[u8], private_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (ct, tag, nonce) = encrypt_aes_gcm(private_key, data)?;
        let mut meta = Vec::with_capacity(12 + 16);
        meta.extend_from_slice(&nonce);
        meta.extend_from_slice(&tag);
        Ok((ct, meta))
    }

    pub fn package_data(&self, packet: &[u8], public_key: &[u8], mode: &str, identity: u64) -> Vec<u8> {
        let mode_bytes = mode.as_bytes();
        let mut payload = Vec::with_capacity(
            8 + public_key.len() +
            8 + packet.len() +
            8 + mode_bytes.len() +
            8
        );

        payload.extend_from_slice(&pack_u64_le(public_key.len() as u64));
        payload.extend_from_slice(public_key);

        payload.extend_from_slice(&pack_u64_le(packet.len() as u64));
        payload.extend_from_slice(packet);

        payload.extend_from_slice(&pack_u64_le(mode_bytes.len() as u64));
        payload.extend_from_slice(mode_bytes);

        payload.extend_from_slice(&pack_u64_le(identity));

        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&pack_u64_le(payload.len() as u64));
        out.extend_from_slice(&payload);
        out
    }
}

impl Deref for SetupNode {
    type Target = Utils;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl DerefMut for SetupNode {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

pub struct Embedding {
    pub embedding: Vec<u8>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub identity: u64,
}

#[derive(Clone, Debug)]
pub struct Unpacked {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub packet: Vec<u8>,
    pub mode: String,
    pub identity: u64,
    pub deobf: Option<Vec<u8>>,
}

pub struct EncryptNode(Utils);
impl EncryptNode {
    pub fn new(party_id: impl Into<String>) -> Self {
        Self(Utils::new(party_id))
    }

    pub fn unpackage_data(&self, data: &[u8]) -> (Vec<u8>, Vec<u8>, String, u64) {
        let mut off = 8; // skip total size
        let pub_len = read_u64_le(data, &mut off) as usize;
        let public_key = data[off..off + pub_len].to_vec();
        off += pub_len;

        let pkt_len = read_u64_le(data, &mut off) as usize;
        let packet = data[off..off + pkt_len].to_vec();
        off += pkt_len;

        let mode_len = read_u64_le(data, &mut off) as usize;
        let mode = String::from_utf8_lossy(&data[off..off + mode_len]).to_string();
        off += mode_len;

        let identity = read_u64_le(data, &mut off);

        (public_key, packet, mode, identity)
    }

    pub fn encrypt_data(&self, packet: &[u8], private_key: &[u8], public_key: &[u8], mode: &str, identity: u64) -> Result<Embedding> {
        let streams = stream_data(mode, packet)?;
        let out = encrypt::map_data(public_key, private_key, identity as usize, streams);
        let chunk = involute::get_chunk_size(&out);
        let mut salt = Vec::with_capacity(private_key.len() + public_key.len());
        salt.extend_from_slice(private_key);
        salt.extend_from_slice(public_key);
        let enc = involute::involute_packet(&out, &salt, chunk)
            .map_err(|_| Error::Mismatch)?;

        Ok(Embedding {
            embedding: enc,
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            identity,
        })
    }

    pub fn cycle_key(&self, encrypted_data: &[u8], old_key: &[u8], new_key: &[u8], public_key: &[u8]) -> Vec<u8> {
        let chunk = involute::get_chunk_size(encrypted_data);
        let mut old_salt = Vec::with_capacity(old_key.len() + public_key.len());
        old_salt.extend_from_slice(old_key);
        old_salt.extend_from_slice(public_key);

        let mut new_salt = Vec::with_capacity(new_key.len() + public_key.len());
        new_salt.extend_from_slice(new_key);
        new_salt.extend_from_slice(public_key);

        involute::cycle_packet(encrypted_data, &old_salt, &new_salt, old_key, new_key, chunk)
            .expect("cycle ok")
    }

    pub fn package_data(&self, emb: &Embedding, mode: &str, identity: u64) -> Result<Vec<u8>> {
        let mode_bytes = mode.as_bytes();
        let mut payload = Vec::new();

        payload.extend_from_slice(&pack_u64_le(emb.public_key.len() as u64));
        payload.extend_from_slice(&emb.public_key);

        payload.extend_from_slice(&pack_u64_le(emb.private_key.len() as u64));
        payload.extend_from_slice(&emb.private_key);

        payload.extend_from_slice(&pack_u64_le(emb.embedding.len() as u64));
        payload.extend_from_slice(&emb.embedding);

        payload.extend_from_slice(&pack_u64_le(mode_bytes.len() as u64));
        payload.extend_from_slice(mode_bytes);

        payload.extend_from_slice(&pack_u64_le(identity));

        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&pack_u64_le(payload.len() as u64));
        out.extend_from_slice(&payload);
        Ok(out)
    }

    pub fn _unpack_encrypted_data(&self, data: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, String, u64) {
        let mut off = 8;

        let pub_len = read_u64_le(data, &mut off) as usize;
        let public_key = data[off..off + pub_len].to_vec();
        off += pub_len;

        let priv_len = read_u64_le(data, &mut off) as usize;
        let private_key = data[off..off + priv_len].to_vec();
        off += priv_len;

        let pkt_len = read_u64_le(data, &mut off) as usize;
        let packet = data[off..off + pkt_len].to_vec();
        off += pkt_len;

        let mode_len = read_u64_le(data, &mut off) as usize;
        let mode = String::from_utf8_lossy(&data[off..off + mode_len]).to_string();
        off += mode_len;

        let identity = read_u64_le(data, &mut off);
        (public_key, private_key, packet, mode, identity)
    }
}

impl Deref for EncryptNode {
    type Target = Utils;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl DerefMut for EncryptNode {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

pub struct DecryptNode(#[allow(dead_code)]Utils);
impl DecryptNode {
    pub fn new(party_id: impl Into<String>) -> Self {
        Self(Utils::new(party_id))
    }

    pub fn collect_packets(&self, packets: &[Vec<u8>]) -> Result<Vec<Unpacked>> {
        packets.iter().map(|p| self.unpackage_data(p)).collect()
    }

    pub fn unpackage_data(&self, data: &[u8]) -> Result<Unpacked> {
        let mut off = 8;

        let pub_len = read_u64_le(data, &mut off) as usize;
        let public_key = data[off..off + pub_len].to_vec();
        off += pub_len;

        let priv_len = read_u64_le(data, &mut off) as usize;
        let private_key = data[off..off + priv_len].to_vec();
        off += priv_len;

        let pkt_len = read_u64_le(data, &mut off) as usize;
        let packet = data[off..off + pkt_len].to_vec();
        off += pkt_len;

        let mode_len = read_u64_le(data, &mut off) as usize;
        let mode = String::from_utf8_lossy(&data[off..off + mode_len]).to_string();
        off += mode_len;

        let identity = read_u64_le(data, &mut off);

        Ok(Unpacked{public_key: public_key.clone(), 
            private_key: private_key.clone(),
            packet: packet.clone(), 
            mode: mode.clone(), 
            identity: identity,
            deobf: None})
    }

    pub fn recover_packets(
        &self,
        packets: &[Unpacked],
    ) -> Result<Vec<Unpacked>> {
        let mut out = Vec::with_capacity(packets.len());
        for p in packets.iter() {
            let chunk = involute::get_chunk_size(&p.packet);
            let mut salt = Vec::with_capacity(p.private_key.len() + p.public_key.len());
            salt.extend_from_slice(&p.private_key);
            salt.extend_from_slice(&p.public_key);

            let deobf = involute::involute_packet(&p.packet, &salt, chunk).map_err(|_| Error::Mismatch)?;

            out.push(Unpacked {
                public_key: p.public_key.clone(),
                private_key: p.private_key.clone(),
                packet: p.packet.clone(),
                mode: p.mode.clone(),
                identity: p.identity,
                deobf: Some(deobf),
            });
        }
        Ok(out)
    }

    pub fn reconstruct_data(
        &self,
        recovered: &[Unpacked],
    ) -> Result<Vec<Vec<u8>>> {
        let n = recovered.len();
        let first_mode = &recovered[0].mode;
        let first_pub = &recovered[0].public_key;

        for r in recovered.iter().skip(1) {
            if &r.mode != first_mode || r.public_key != *first_pub {
                return Err(Error::Mismatch);
            }
        }

        let mut identities = vec![false; n];
        for r in recovered {
            let id = r.identity as usize;
            if id >= n || identities[id] {
                return Err(Error::BadIdentities);
            }
            identities[id] = true;
        }
        if identities.iter().any(|b| !*b) {
            return Err(Error::BadIdentities);
        }

        // reorder by identity
        let mut privs: Vec<Vec<u8>> = vec![Vec::new(); n];
        let mut datas: Vec<Vec<u8>> = vec![Vec::new(); n];
        for r in recovered {
            let id = r.identity as usize;
            privs[id] = r.private_key.clone();
            datas[id] = r.deobf.clone().expect("deobf missing");
        }

        let size = 1 << 8;
        let out = decrypt::inv_data(first_pub, &privs, datas, size);
        Ok(out)
    }

    pub fn reassemble_data(&self, streams: &[Vec<u8>], mode: &str) -> Result<Vec<u8>> {
        recombine_data(mode, streams)
    }

    pub fn decrypt_data_ctr(&self, ciphertext: &[u8], nonce8: &[u8; 8], private_key: &[u8]) -> Vec<u8> {
        decrypt_aes_ctr(private_key, nonce8, ciphertext)
    }

    pub fn _decrypt_data_gcm(&self, ciphertext: &[u8], metadata: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
        let (nonce, tag) = metadata.split_at(12);
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let tag: [u8; 16] = tag.try_into().unwrap();
        Ok(decrypt_aes_gcm(private_key, &nonce, ciphertext, &tag)?)
    }

    pub fn obfuscate_data(
        &self,
        packet: &[u8],
        private_key: &[u8],
        low: u64,
        high: u64,
        test: f32,
    ) -> Result<(Vec<u8>, usize)> {
        let chunk = involute::get_chunk_size(packet);
        let inv = involute::cond_involute_packet(packet, private_key, chunk, low, high, test)
            .map_err(|_| Error::Mismatch)?;
        Ok((inv, chunk))
    }
}

/* =========================
   High-level helpers
   ========================= */

pub fn setup_node(
    data: &[u8],
    cond_low: f32,
    cond_high: f32,
    encrypt: bool,
) -> Result<(/* public */ (Vec<u8>, Vec<u8>), /* private */ (Vec<u8>, u64, u64, Vec<u8>))> {
    let node = SetupNode::new("Authoriser");
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);

    let public_key = node.gen_public_key(&seed).expect("pk");
    let private_key = node.0.gen_private_key("obf_privateKey", &seed).expect("sk");

    let (encrypted, nonce) = if encrypt {
        let (ct, nonce8) = node.encrypt_data(data, &private_key);
        (ct, nonce8.to_vec())
    } else {
        (data.to_vec(), Vec::new())
    };

    let test_val = (cond_low + cond_high) / 2.0;
    let (lo, hi) = node.implement_conditions(cond_low, cond_high, &private_key)?;
    let (obf, _) = node
        .obfuscate_data(&encrypted, &private_key, lo, hi, test_val)
        .expect("obf");

    Ok(( (obf, public_key.clone()),
      (private_key, lo, hi, nonce) ))
}

pub fn distribute_data(public_data: &(Vec<u8>, Vec<u8>), stream_mode: &str, num_parties: u64) -> Result<Vec<Vec<u8>>> {
    let node = SetupNode::new("");
    let mode = format!("{}{}", stream_mode, num_parties);
    let mut out = Vec::with_capacity(num_parties as usize);
    for i in 0..num_parties {
        let pkt = node.package_data(&public_data.0, &public_data.1, &mode, i);
        out.push(pkt);
    }
    Ok(out)
}

pub fn encrypt_node(packet: &[u8], node_label: &str) -> Result<Vec<u8>> {
    let enc = EncryptNode::new(node_label);
    let (public_key, data_packet, mode, identity) = enc.unpackage_data(packet);
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);

    let private_key = enc.0.gen_private_key("label_privateKey", &seed).expect("sk");
    let emb = enc
        .encrypt_data(&data_packet, &private_key, &public_key, &mode, identity)
        .expect("embed");
    Ok(enc.package_data(&emb, &mode, identity)?)
}

pub fn cycle_key(encrypted_packet: &[u8], node_label: &str) -> Result<Vec<u8>> {
    let enc = EncryptNode::new(node_label);
    let (public_key, private_key, packet, mode, identity) = enc._unpack_encrypted_data(encrypted_packet);

    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let new_private_key = enc.0.gen_private_key("cycled_key", &seed).expect("sk");

    let cycled = enc.cycle_key(&packet, &private_key, &new_private_key, &public_key);
    let emb = Embedding {
        embedding: cycled,
        private_key: new_private_key.clone(),
        public_key: public_key.clone(),
        identity,
    };
    Ok(enc.package_data(&emb, &mode, identity)?)
}

pub fn decrypt_node(
    private_data: &(Vec<u8>, u64, u64, Vec<u8>),
    test_value: f32,
    encrypt: bool,
    packets: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let (ref priv_key, lo, hi, ref nonce) = *private_data;

    let dec = DecryptNode::new("Veriphier");
    let collected = dec.collect_packets(packets)?;
    let recovered = dec.recover_packets(&collected)?;
    let streams = dec.reconstruct_data(&recovered)?;
    let mode = &collected[0].mode;
    println!("Mode: {}\n", mode);
    let recombined = dec.reassemble_data(&streams, mode)?;

    let (recov, _) = dec.obfuscate_data(&recombined, priv_key, lo, hi, test_value)?;
    if encrypt {
        // CTR path
        let nonce8: [u8; 8] = nonce.as_slice().try_into().map_err(|_| Error::AesGcm)?; // reusing error
        Ok(dec.decrypt_data_ctr(&recov, &nonce8, priv_key))
    } else {
        Ok(recov)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_e2() {
        let data: Vec<u8> = (0..100).collect();
        let mode = "E2";
        let streams = stream_data(mode, &data).unwrap();
        let rec = recombine_data(mode, &streams).unwrap();
        assert_eq!(rec, data); // exact (no padding needed)
    }

    #[test]
    fn roundtrip_e3_with_padding() {
        let data: Vec<u8> = (0..101).collect(); // not divisible by 3
        let mode = "E3";
        let streams = stream_data(mode, &data).unwrap();
        // recombined returns padded length; trim to original to compare
        let rec = recombine_data(mode, &streams).unwrap();
        assert_eq!(&rec[..data.len()], &data[..]);
        assert_eq!(rec.len() % 3, 0);
    }

    #[test]
    fn roundtrip_k2() {
        let data: Vec<u8> = (0..ninety_six()).map(|i| i as u8).collect();
        let mode = "K2";
        let streams = stream_data(mode, &data).unwrap();
        let rec = recombine_data(mode, &streams).unwrap();
        assert_eq!(rec, data); // exact (no padding needed)
    }

    #[test]
    fn roundtrip_k3() {
        let data: Vec<u8> = (0..ninety_six()).map(|i| i as u8).collect();
        let mode = "K3";
        let streams = stream_data(mode, &data).unwrap();
        let rec = recombine_data(mode, &streams).unwrap();
        assert_eq!(rec, data);
    }

    fn ninety_six() -> usize { 96 }
}