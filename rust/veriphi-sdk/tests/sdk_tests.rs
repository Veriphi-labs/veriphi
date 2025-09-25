use rand::RngCore;

use veriphi_sdk as vc;

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::rng().fill_bytes(&mut v);
    v
}

//////////////////////////////
// Tests for GCM encryption //
//////////////////////////////

#[test]
fn aes_gcm_basic() {
    let private_key = rand_bytes(256);
    let plaintext = b"testing AES implementation in rust".to_vec();

    let (ciphertext, tag, nonce) = vc::encrypt_aes_gcm(&private_key, &plaintext).unwrap();
    let recovered = vc::decrypt_aes_gcm(&private_key, &nonce, &ciphertext, &tag).unwrap();

    assert_ne!(ciphertext, plaintext);
    assert_eq!(recovered, plaintext);
}

#[test]
fn aes_gcm_detects_ciphertext_tampering() {
    let private_key = rand_bytes(256);
    let plaintext = b"testing AES implementation in rust".to_vec();

    let (mut ciphertext, tag, nonce) = vc::encrypt_aes_gcm(&private_key, &plaintext).unwrap();
    // Flip one bit in ciphertext
    ciphertext[0] ^= 1;

    assert!(vc::decrypt_aes_gcm(&private_key, &nonce, &ciphertext, &tag).is_err());
}

#[test]
fn aes_gcm_detects_tag_tampering() {
    let private_key = rand_bytes(256);
    let plaintext = b"testing AES implementation in rust".to_vec();

    let (ciphertext, mut tag, nonce) = vc::encrypt_aes_gcm(&private_key, &plaintext).unwrap();
    // Flip one bit in tag
    tag[0] ^= 1;

    assert!(vc::decrypt_aes_gcm(&private_key, &nonce, &ciphertext, &tag).is_err());
}

#[test]
fn aes_gcm_detects_wrong_nonce() {
    let private_key = rand_bytes(256);
    let plaintext = b"testing AES implementation in rust".to_vec();

    let (ciphertext, tag, _nonce) = vc::encrypt_aes_gcm(&private_key, &plaintext).unwrap();
    let wrong_nonce: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
    let wrong_nonce_arr: [u8; 12] = wrong_nonce.try_into().unwrap();

    assert!(vc::decrypt_aes_gcm(&private_key, &wrong_nonce_arr, &ciphertext, &tag).is_err());
}

//////////////////////////////
// Tests for CTR encryption //
//////////////////////////////

#[test]
fn aes_ctr_basic() {
    let private_key = rand_bytes(256);
    let plaintext = b"testing AES implementation in rust".to_vec();

    let (ciphertext, nonce) = vc::encrypt_aes_ctr(&private_key, &plaintext);
    let recovered = vc::decrypt_aes_ctr(&private_key, &nonce, &ciphertext);

    assert_ne!(ciphertext, plaintext);
    assert_eq!(recovered, plaintext);
}

#[test]
fn aes_ctr_no_tampering_detection() {
    // CTR does NOT authenticate
    let private_key = rand_bytes(256);
    let plaintext = b"testing AES implementation in rust".to_vec();

    let (mut ciphertext, nonce) = vc::encrypt_aes_ctr(&private_key, &plaintext);
    // Flip one bit
    ciphertext[0] ^= 1;

    let corrupted = vc::decrypt_aes_ctr(&private_key, &nonce, &ciphertext);
    assert_ne!(corrupted, plaintext);
    assert_eq!(corrupted.len(), plaintext.len());
}

#[test]
fn aes_ctr_wrong_nonce_produces_garbage() {
    let private_key = rand_bytes(256);
    let plaintext = b"testing AES implementation in rust".to_vec();

    let (ciphertext, _nonce) = vc::encrypt_aes_ctr(&private_key, &plaintext);
    let wrong_nonce_vec: Vec<u8> = (0..8).map(|_| rand::random::<u8>()).collect();
    let wrong_nonce_arr: [u8; 8] = wrong_nonce_vec.try_into().unwrap();

    let garbage = vc::decrypt_aes_ctr(&private_key, &wrong_nonce_arr, &ciphertext);
    assert_ne!(garbage, plaintext);
    assert_eq!(garbage.len(), plaintext.len());
}

#[test]
fn aes_ctr_deterministic_with_same_nonce() -> Result<(),vc::Error> {
    let private_key = rand_bytes(256);
    let plaintext  = b"testing AES implementation in rust".to_vec();
    let fixed_nonce = b"12345678".to_vec();

    let c1 = vc::_encrypt_aes_ctr_with_nonce(&private_key, &plaintext, &fixed_nonce)?;
    let c2 = vc::_encrypt_aes_ctr_with_nonce(&private_key, &plaintext, &fixed_nonce)?;
    assert_eq!(c1, c2);
    Ok(())
}

/////////////////////
// SetupNode tests //
/////////////////////

#[test]
fn involute_condition_true() {
    let mut test_data = vec![0u8; 1000];
    rand::rng().fill_bytes(&mut test_data);

    let node_a = vc::SetupNode::new("A");
    let master_seed = rand_bytes(32);
    let private_key = node_a.gen_private_key("master_private_key", &master_seed).unwrap();
    let (low_value, high_value) = node_a.implement_conditions(-1.0, 1.0, &private_key).unwrap();

    let (obfuscated, _chunk) = node_a
        .obfuscate_data(&test_data, &private_key, low_value, high_value, 0.0)
        .unwrap();

    assert_ne!(obfuscated, test_data);
}

#[test]
fn involute_failed_condition() {
    let mut test_data = vec![0u8; 100];
    rand::rng().fill_bytes(&mut test_data);

    let node_a = vc::SetupNode::new("A");
    let master_seed = rand_bytes(32);
    let private_key = node_a.gen_private_key("master_private_key", &master_seed).unwrap();
    let (low_value, high_value) = node_a.implement_conditions(-1.0, 1.0, &private_key).unwrap();

    let (obfuscated, _chunk) = node_a
        .obfuscate_data(&test_data, &private_key, low_value, high_value, 0.0)
        .unwrap();

    assert_ne!(obfuscated, test_data);
    let mut a = obfuscated.clone(); a.sort_unstable();
    let mut b = test_data.clone();  b.sort_unstable();
    assert_eq!(a, b);
    let (recovered, _c2) = node_a
        .obfuscate_data(&obfuscated, &private_key, low_value, high_value, 0.5)
        .unwrap();
    assert_eq!(recovered, test_data);
    let (recovered_false, _c3) = node_a
        .obfuscate_data(&obfuscated, &private_key, low_value, high_value, 10.0)
        .unwrap();
    assert_ne!(recovered_false, test_data);
}

//////////////////////////
// Full process (SDK)   //
//////////////////////////

#[test]
fn two_way_decryption_e_style() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "E", 2).unwrap();
    let auth_packet = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet = vc::encrypt_node(&packets[1], "agent").unwrap();
    let decrypted = vc::decrypt_node(&private_data, 1.0, true, &[auth_packet, agent_packet]).unwrap();
    assert_eq!(decrypted, test_data);
}

#[test]
fn two_way_decryption_k_style() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "K", 2).unwrap();
    let auth_packet = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet = vc::encrypt_node(&packets[1], "agent").unwrap();
    let decrypted = vc::decrypt_node(&private_data, 1.0, true, &[auth_packet, agent_packet]).unwrap();
    assert_eq!(decrypted, test_data);
}

#[test]
fn three_way_decryption_e_style() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "E", 3).unwrap();
    let auth_packet   = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet  = vc::encrypt_node(&packets[1], "agent").unwrap();
    let target_packet = vc::encrypt_node(&packets[2], "target").unwrap();

    let decrypted = vc::decrypt_node(&private_data, 1.0, true, &[auth_packet, agent_packet, target_packet]).unwrap();
    assert_eq!(decrypted, test_data);
}

#[test]
fn three_way_decryption_k_style() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "K", 3).unwrap();
    let auth_packet   = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet  = vc::encrypt_node(&packets[1], "agent").unwrap();
    let target_packet = vc::encrypt_node(&packets[2], "target").unwrap();

    let decrypted = vc::decrypt_node(&private_data, 1.0, true, &[auth_packet, agent_packet, target_packet]).unwrap();
    assert_eq!(decrypted, test_data);
}

#[test]
fn public_key_decryption_failure() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "K", 3).unwrap();
    let auth_packet   = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet0 = vc::encrypt_node(&packets[1], "agent").unwrap();
    let target_packet = vc::encrypt_node(&packets[2], "target").unwrap();

    // Unpack, modify public key, repack
    let dn = vc::DecryptNode::new("");
    let agent_data = dn.unpackage_data(&agent_packet0).unwrap();
    let mut mod_pub = agent_data.public_key.clone();
    mod_pub.swap(0, 1);

    let en = vc::EncryptNode::new("");
    let modified = vc::Embedding {
        embedding: agent_data.packet.clone(),
        private_key: agent_data.private_key.clone(),
        public_key: mod_pub,
        identity: agent_data.identity,
    };
    let agent_packet = en.package_data(&modified, &agent_data.mode, agent_data.identity).unwrap();

    // Depending on your error propagation, either we get Err, or an incorrect decryption.
    match vc::decrypt_node(&private_data, 1.0, true, &[auth_packet.clone(), agent_packet.clone(), target_packet.clone()]) {
        Ok(decrypted) => assert_ne!(decrypted, test_data),
        Err(_) => (), // also acceptable
    }
}

#[test]
fn public_key_decryption_catastrophic_failure_3() {
    let mut test_data = vec![0u8; 600];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "E", 3).unwrap();
    let auth_packet   = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet0 = vc::encrypt_node(&packets[1], "agent").unwrap();
    let target_packet = vc::encrypt_node(&packets[2], "Domain").unwrap();

    let dn = vc::DecryptNode::new("");
    let agent_data = dn.unpackage_data(&agent_packet0).unwrap();

    // Replace public key with a totally unrelated one
    let sn = vc::SetupNode::new("__");
    let new_pub = sn.gen_public_key(&rand_bytes(32)).unwrap();

    let en = vc::EncryptNode::new("");
    let modified = vc::Embedding {
        embedding: agent_data.packet.clone(),
        private_key: agent_data.private_key.clone(),
        public_key: new_pub,
        identity: agent_data.identity,
    };
    let agent_packet = en.package_data(&modified, &agent_data.mode, agent_data.identity).unwrap();

    // Expect failure
    assert!(vc::decrypt_node(&private_data, 1.0, true, &[auth_packet, agent_packet, target_packet]).is_err());
}

#[test]
fn key_cycling() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "E", 3).unwrap();

    let auth_packet   = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet0 = vc::encrypt_node(&packets[1], "agent").unwrap();
    let target_packet = vc::encrypt_node(&packets[2], "target").unwrap();

    let cycled_agent_packet = vc::cycle_key(&agent_packet0, "agent").unwrap();

    let decrypted = vc::decrypt_node(&private_data, 1.0, true, &[auth_packet, cycled_agent_packet, target_packet]).unwrap();
    assert_eq!(decrypted, test_data);
}

#[test]
fn private_key_decryption_failure_3() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "K", 3).unwrap();

    let auth_packet   = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet0 = vc::encrypt_node(&packets[1], "agent").unwrap();
    let target_packet = vc::encrypt_node(&packets[2], "target").unwrap();

    // Unpack, tweak private key bytes, repackage
    let dn = vc::DecryptNode::new("");
    let agent_data = dn.unpackage_data(&agent_packet0).unwrap();

    let mut mod_priv = agent_data.private_key.clone();
    mod_priv.swap(0, 1);

    let en = vc::EncryptNode::new("");
    let modified = vc::Embedding {
        embedding: agent_data.packet.clone(),
        private_key: mod_priv,
        public_key: agent_data.public_key.clone(),
        identity: agent_data.identity,
    };
    let agent_packet = en.package_data(&modified, &agent_data.mode, agent_data.identity).unwrap();

    let decrypted = vc::decrypt_node(&private_data, 1.0, true, &[auth_packet, agent_packet, target_packet]).unwrap();
    assert_ne!(decrypted, test_data);
}

#[test]
fn private_key_decryption_failure_2() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "E", 2).unwrap();

    let auth_packet   = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet0 = vc::encrypt_node(&packets[1], "agent").unwrap();

    let dn = vc::DecryptNode::new("");
    let agent_data = dn.unpackage_data(&agent_packet0).unwrap();

    let mut mod_priv = agent_data.private_key.clone();
    mod_priv.swap(0, 1);

    let en = vc::EncryptNode::new("");
    let modified = vc::Embedding {
        embedding: agent_data.packet.clone(),
        private_key: mod_priv,
        public_key: agent_data.public_key.clone(),
        identity: agent_data.identity,
    };
    let agent_packet = en.package_data(&modified, &agent_data.mode, agent_data.identity).unwrap();

    let decrypted = vc::decrypt_node(&private_data, 1.0, true, &[auth_packet, agent_packet]).unwrap();
    assert_ne!(decrypted, test_data);
}

#[test]
fn condition_failure_3() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0,true).unwrap();
    let packets = vc::distribute_data(&public_data, "E", 3).unwrap();

    let auth_packet   = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet  = vc::encrypt_node(&packets[1], "agent").unwrap();
    let target_packet = vc::encrypt_node(&packets[2], "target").unwrap();

    let decrypted = vc::decrypt_node(&private_data, -1.0, true, &[auth_packet, agent_packet, target_packet]).unwrap();
    assert_ne!(decrypted, test_data);
}

#[test]
fn condition_failure_2() {
    let mut test_data = vec![0u8; 300];
    rand::rng().fill_bytes(&mut test_data);

    let (public_data, private_data) = vc::setup_node(&test_data, 0.0, 10.0, true).unwrap();
    let packets = vc::distribute_data(&public_data, "E", 2).unwrap();

    let auth_packet   = vc::encrypt_node(&packets[0], "authoriser").unwrap();
    let agent_packet  = vc::encrypt_node(&packets[1], "agent").unwrap();

    let decrypted = vc::decrypt_node(&private_data, 11.0, true, &[auth_packet, agent_packet]).unwrap();
    assert_ne!(decrypted, test_data);
}


