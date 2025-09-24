from veriphi_core import utils, interface
import numpy as np
import pytest
import os
import pytest

############################
# Tests for GCM encryption #
############################

def test_aes_gcm_basic():
    private_key = os.urandom(256)
    plaintext = b"testing AES implementation in python"
    ciphertext, tag, nonce = utils.encrypt_AES_GCM(private_key, plaintext)
    recovtext = utils.decrypt_AES_GCM(private_key, nonce, ciphertext, tag)
    assert ciphertext != plaintext
    assert recovtext == plaintext

def test_aes_gcm_detects_ciphertext_tampering():
    private_key = os.urandom(256)
    plaintext = b"testing AES implementation in python"
    ciphertext, tag, nonce = utils.encrypt_AES_GCM(private_key, plaintext)
    
    # Modify one bit of ciphertext
    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[0] ^= 1
    
    with pytest.raises(ValueError):
        utils.decrypt_AES_GCM(private_key, nonce, bytes(modified_ciphertext), tag)

def test_aes_gcm_detects_tag_tampering():
    private_key = os.urandom(256)
    plaintext = b"testing AES implementation in python"
    ciphertext, tag, nonce = utils.encrypt_AES_GCM(private_key, plaintext)
    
    # Modify one bit of tag
    modified_tag = bytearray(tag)
    modified_tag[0] ^= 1
    
    with pytest.raises(ValueError):
        utils.decrypt_AES_GCM(private_key, nonce, ciphertext, bytes(modified_tag))

def test_aes_gcm_detects_wrong_nonce():
    private_key = os.urandom(256)
    plaintext = b"testing AES implementation in python"
    ciphertext, tag, nonce = utils.encrypt_AES_GCM(private_key, plaintext)
    
    # Use wrong nonce
    wrong_nonce = os.urandom(12)
    
    with pytest.raises(ValueError):
        utils.decrypt_AES_GCM(private_key, wrong_nonce, ciphertext, tag)



############################
# Tests for CTR encryption #
############################

def test_aes_ctr_basic():
    private_key = os.urandom(256)
    plaintext = b"testing AES implementation in python"
    ciphertext, nonce = utils.encrypt_AES_CTR(private_key, plaintext)
    recovtext = utils.decrypt_AES_CTR(private_key, nonce, ciphertext)
    
    assert ciphertext != plaintext
    assert recovtext == plaintext

def test_aes_ctr_no_tampering_detection():
    """CTR mode does NOT detect tampering - decryption succeeds but produces garbage"""
    private_key = os.urandom(256)
    plaintext = b"testing AES implementation in python"
    ciphertext, nonce = utils.encrypt_AES_CTR(private_key, plaintext)
    
    # Modify one bit of ciphertext
    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[0] ^= 1
    
    # CTR decryption succeeds but produces corrupted data
    corrupted_plaintext = utils.decrypt_AES_CTR(private_key, nonce, bytes(modified_ciphertext))
    
    # The decryption succeeds (no exception)
    assert corrupted_plaintext != plaintext
    assert len(corrupted_plaintext) == len(plaintext)  # Same length though

def test_aes_ctr_wrong_nonce_produces_garbage():
    """CTR with wrong nonce produces garbage output, no authentication failure"""
    private_key = os.urandom(256)
    plaintext = b"testing AES implementation in python"
    ciphertext, nonce = utils.encrypt_AES_CTR(private_key, plaintext)
    
    # Use wrong nonce
    wrong_nonce = os.urandom(8)  # CTR uses 16-byte nonce
    garbage_output = utils.decrypt_AES_CTR(private_key, wrong_nonce, ciphertext)
    assert garbage_output != plaintext
    assert len(garbage_output) == len(plaintext)

def test_aes_ctr_bit_flipping_attack():
    """Demonstrates CTR's vulnerability to bit-flipping attacks"""
    private_key = os.urandom(256)
    plaintext = b"ATTACK AT DAWN"
    ciphertext, nonce = utils.encrypt_AES_CTR(private_key, plaintext)
    
    # Test for cipher modification
    target_change = b"ATTACK" 
    desired_text = b"DEFEND"
    xor_diff = bytes(a ^ b for a, b in zip(target_change, desired_text))
    modified_ciphertext = bytearray(ciphertext)
    for i, byte_diff in enumerate(xor_diff):
        modified_ciphertext[i] ^= byte_diff
    modified_plaintext = utils.decrypt_AES_CTR(private_key, nonce, bytes(modified_ciphertext))
    
    assert modified_plaintext.startswith(b"DEFEND")
    assert modified_plaintext != plaintext

def test_aes_ctr_deterministic_with_same_nonce():
    """CTR is deterministic - same key+nonce produces same ciphertext"""
    private_key = os.urandom(256)
    plaintext = b"testing AES implementation in python"
    fixed_nonce = b"12345678"
    
    # Encrypt twice with same nonce
    cipher1 = utils._encrypt_AES_CTR_with_nonce(private_key, plaintext, fixed_nonce)
    cipher2 = utils._encrypt_AES_CTR_with_nonce(private_key, plaintext, fixed_nonce)
    assert cipher1 == cipher2

###################
# Test setup node #
###################

def test_involute_condition_true():
    rng = np.random.default_rng()
    test_data = rng.integers(0, 256, size = (1000,), dtype=np.uint8)
    node_a = interface.SetupNode("A")
    master_seed = os.urandom(32)
    private_key = node_a.gen_private_key("master_private_key",np.frombuffer(master_seed,dtype=np.uint8))
    low_value, high_value = node_a.implement_conditions(-1.0, 1.0, private_key)
    obv_packet,_ = node_a.obfuscate_data(test_data, private_key, low_value, high_value, 0.0)

    assert not np.array_equal(obv_packet, test_data)

def test_involute_failed_condition():
    rng = np.random.default_rng()
    test_data = rng.integers(0, 256, size = (100,), dtype=np.uint8)
    node_a = interface.SetupNode("A")
    master_seed = os.urandom(32)
    private_key = node_a.gen_private_key("master_private_key",np.frombuffer(master_seed,dtype=np.uint8))
    low_value, high_value = node_a.implement_conditions(-1.0, 1.0, private_key)
    obv_packet,_ = node_a.obfuscate_data(test_data, private_key, low_value, high_value, 0.0)
    
    # Obfuscated packet should not resemble original, but should have the same values
    assert not np.array_equal(obv_packet, test_data)
    assert np.array_equal(np.sort(obv_packet), np.sort(test_data))
    
    # Recovered packet should be exactly the same as the original
    recov_packet,_ = node_a.obfuscate_data(obv_packet,private_key, low_value, high_value , 0.5)
    assert np.array_equal(recov_packet,test_data)

    # Attempt to recover the original with a failed condition should lead to a different array
    recov_packet_false,_ = node_a.obfuscate_data(obv_packet, private_key, low_value, high_value, 10.0)
    assert not np.array_equal(recov_packet_false,test_data)

#####################
# Test full process #
#####################

def test_2_way_decryption_E_style():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B] = interface.distribute_data(public_data,"E",2)
    # Encrypt the portions
    auth_packet = interface.encrypt_node(packet_A,"authoriser")
    agent_packet= interface.encrypt_node(packet_B,"agent")
    # Decrypt the data
    decrypted_data = interface.decrypt_node(private_data,1.0,False,auth_packet,agent_packet)
    assert np.all(test_data == decrypted_data), "Recovered data and initial data shoulf be the same"
    
def test_2_way_decryption_K_style():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B] = interface.distribute_data(public_data,"K",2)
    # Encrypt the portions
    auth_packet = interface.encrypt_node(packet_A,"authoriser")
    agent_packet= interface.encrypt_node(packet_B,"agent")
    # Decrypt the data
    decrypted_data = interface.decrypt_node(private_data,1.0,False,auth_packet,agent_packet)
    assert np.all(test_data == decrypted_data), "Recovered data and initial data shoulf be the same"
    

def test_3_way_decryption_E_style():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B,packet_C] = interface.distribute_data(public_data,"E",3)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    target_packet= interface.encrypt_node(packet_C,"target")
    # Decrypt the data
    decrypted_data = interface.decrypt_node(private_data,1.0,False,auth_packet,agent_packet,target_packet)
    assert np.all(test_data == decrypted_data), "Recovered data and initial data shoulf be the same"
    
def test_3_way_decryption_K_style():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B,packet_C] = interface.distribute_data(public_data,"K",3)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    target_packet= interface.encrypt_node(packet_C,"target")
    # Decrypt the data
    decrypted_data = interface.decrypt_node(private_data,1.0,False,auth_packet,agent_packet,target_packet)
    assert np.all(test_data == decrypted_data), "Recovered data and initial data shoulf be the same"

def test_public_key_decryption_failure():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B,packet_C] = interface.distribute_data(public_data,"K",3)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    target_packet= interface.encrypt_node(packet_C,"target")
    # Now modify one of the public keys

    decrypt_node = interface.DecryptNode("")
    agent_data  = decrypt_node.unpackage_data(agent_packet)
    agent_public_key = np.frombuffer(agent_data["public_key"],dtype=np.uint8)
    mod_agent_public_key = agent_public_key.copy()
    mod_agent_public_key[0] = agent_public_key[1]
    mod_agent_public_key[1] = agent_public_key[0]
    encrypt_node = interface.EncryptNode("")
    agent_packet = {"embedding":agent_data["packet"].tobytes(),
                "private_key":agent_data["private_key"],
                "public_key":mod_agent_public_key.tobytes()}
    agent_packet = encrypt_node.package_data(agent_packet,agent_data["mode"],agent_data["identity"])
    # Decrypt the data
    try:
        decrypted_data = interface.decrypt_node(private_data,1.0,False,auth_packet,agent_packet,target_packet)
    except Exception as e:
        print(f"Recovery failed: {e}")
        return
    assert not np.array_equal(decrypted_data, test_data), "Recovered data and initial data shoulf be the same"

"""
def test_public_key_decryption_catastrophic_failure_2():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(600,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B] = interface.distribute_data(public_data,"K",2)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    # Now modify one of the public keys

    decrypt_node = interface.DecryptNode("")
    agent_data  = decrypt_node.unpackage_data(agent_packet)
    setup_node = interface.SetupNode("__")
    encrypt_node = interface.EncryptNode("")
    agent_packet = {"embedding":agent_data["packet"].tobytes(),
                "private_key":np.frombuffer(agent_data["private_key"],dtype=np.uint8),
                "public_key":np.frombuffer(setup_node.gen_public_key(np.frombuffer(os.urandom(32), np.uint8)))}
    agent_packet = encrypt_node.package_data(agent_packet,agent_data["mode"],agent_data["identity"])
    # Decrypt the data
    with pytest.raises(Exception):
        _ = interface.decrypt_nodet(private_data,1.0,auth_packet,agent_packet)
"""

def test_public_key_decryption_catastrophic_failure_3():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(600,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B,packet_C] = interface.distribute_data(public_data,"E",3)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    target_packet= interface.encrypt_node(packet_C,"Domain")
    # Now modify one of the public keys

    decrypt_node = interface.DecryptNode("")
    agent_data  = decrypt_node.unpackage_data(agent_packet)
    setup_node = interface.SetupNode("__")
    encrypt_node = interface.EncryptNode("")
    agent_packet = {"embedding":agent_data["packet"].tobytes(),
                "private_key":agent_data["private_key"],
                "public_key":setup_node.gen_public_key(np.frombuffer(os.urandom(32), np.uint8))}
    agent_packet = encrypt_node.package_data(agent_packet,agent_data["mode"],agent_data["identity"])
    # Decrypt the data
    with pytest.raises(Exception):
        _ = interface.decrypt_node_intersect(private_data,1.0,auth_packet,agent_packet,target_packet)

def test_key_cycling():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B,packet_C] = interface.distribute_data(public_data,"E",3)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    target_packet= interface.encrypt_node(packet_C,"target")
    cycled_agent_packet = interface.cycle_key(agent_packet,"agent")
    # Decrypt the data
    decrypted_data = interface.decrypt_node(private_data,1.0,False,auth_packet,cycled_agent_packet,target_packet)
    print(decrypted_data)
    print(test_data)
    assert np.all(test_data == decrypted_data), "Recovered data and initial data shoulf be the same"
    
def test_private_key_decryption_failure_3():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B,packet_C] = interface.distribute_data(public_data,"K",3)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    target_packet= interface.encrypt_node(packet_C,"target")
    # Now modify one of the public keys

    decrypt_node = interface.DecryptNode("")
    agent_data  = decrypt_node.unpackage_data(agent_packet)
    agent_private_key = np.frombuffer(agent_data["private_key"],dtype=np.uint8)
    mod_agent_private_key = agent_private_key.copy()
    mod_agent_private_key[0] = agent_private_key[1]
    mod_agent_private_key[1] = agent_private_key[0]
    encrypt_node = interface.EncryptNode("")
    agent_packet = {"embedding":agent_data["packet"].tobytes(),
                "private_key":mod_agent_private_key.tobytes(),
                "public_key":agent_data["public_key"]}
    agent_packet = encrypt_node.package_data(agent_packet,agent_data["mode"],agent_data["identity"])
    # Decrypt the data
    decrypted_data = interface.decrypt_node(private_data,1.0,False,auth_packet,agent_packet,target_packet)
    assert not np.array_equal(decrypted_data, test_data), "Recovered data and initial data shoulf be the same"

def test_private_key_decryption_failure_2():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B] = interface.distribute_data(public_data,"E",2)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    # Now modify one of the public keys

    decrypt_node = interface.DecryptNode("")
    agent_data  = decrypt_node.unpackage_data(agent_packet)
    agent_private_key = np.frombuffer(agent_data["private_key"],dtype=np.uint8)
    mod_agent_private_key = agent_private_key.copy()
    mod_agent_private_key[0] = agent_private_key[1]
    mod_agent_private_key[1] = agent_private_key[0]
    encrypt_node = interface.EncryptNode("")
    agent_packet = {"embedding":agent_data["packet"].tobytes(),
                "private_key":mod_agent_private_key.tobytes(),
                "public_key":agent_data["public_key"]}
    agent_packet = encrypt_node.package_data(agent_packet,agent_data["mode"],agent_data["identity"])
    # Decrypt the data
    decrypted_data = interface.decrypt_node(private_data,1.0,False,auth_packet,agent_packet)
    assert not np.array_equal(decrypted_data, test_data), "Recovered data and initial data shoulf be the same"

def test_condition_failure_3():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B,packet_C] = interface.distribute_data(public_data,"E",3)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    target_packet= interface.encrypt_node(packet_C,"target")
    # Decrypt the data
    decrypted_data = interface.decrypt_node(private_data,-1.0,False,auth_packet,agent_packet,target_packet)
    assert not np.all(test_data == decrypted_data), "Recovered data and initial data shoulf be the different"

def test_condition_failure_2():
    rng = np.random.default_rng()
    test_data = rng.integers(0,256, size=(300,), dtype=np.uint8)
    # Setup the network
    public_data, private_data = interface.setup_node(test_data, 0.0, 10.0)
    [packet_A,packet_B] = interface.distribute_data(public_data,"E",2)
    # Encrypt the portions
    auth_packet  = interface.encrypt_node(packet_A,"authoriser")
    agent_packet = interface.encrypt_node(packet_B,"agent")
    # Decrypt the data
    decrypted_data = interface.decrypt_node(private_data,11.0,False,auth_packet,agent_packet)
    assert not np.all(test_data == decrypted_data), "Recovered data and initial data shoulf be the different"


if __name__ == "__main__":
    test_public_key_decryption_failure()


