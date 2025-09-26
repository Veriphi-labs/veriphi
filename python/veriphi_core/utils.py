import Crypto.Protocol.KDF, Crypto.Cipher.AES
from Crypto.Hash import SHA256
import numpy as np
from numpy.typing import NDArray
import os

#############################
# Standard crypto utilities #
#############################

def derive_encryption_key(private_key: bytes, count: int = 250_000, context: bytes = b"setup_encryption") -> bytes:
    """Derive a consistent encryption key from private key."""
    return Crypto.Protocol.KDF.PBKDF2(private_key, context, count=count, dkLen=32, hmac_hash_module=SHA256 )

def encrypt_AES_GCM(private_key: bytes, plaintext: bytes, num_iter: int = 250_000):
    encrypt_key = derive_encryption_key(private_key, count = num_iter)
    nonce = os.urandom(12)
    aes_cipher = Crypto.Cipher.AES.new(encrypt_key, Crypto.Cipher.AES.MODE_GCM, nonce = nonce)
    cipher_text, tag = aes_cipher.encrypt_and_digest(plaintext)
    return cipher_text, tag, nonce

def decrypt_AES_GCM(private_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, num_iter: int = 250_000):
    encrypt_key = derive_encryption_key(private_key, count = num_iter)
    aes_cipher = Crypto.Cipher.AES.new(encrypt_key, Crypto.Cipher.AES.MODE_GCM, nonce=nonce)
    try:
        return aes_cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        raise ValueError("Decryption failed - data may be corrupted or key is wrong") from e

def encrypt_AES_CTR(private_key: bytes, plaintext: bytes, num_iter: int = 250_000):
    encrypt_key = derive_encryption_key(private_key, count = num_iter)
    nonce = os.urandom(8)
    aes_cipher = Crypto.Cipher.AES.new(encrypt_key, Crypto.Cipher.AES.MODE_CTR, nonce=nonce)
    cipher_text = aes_cipher.encrypt(plaintext)
    return cipher_text, nonce

def decrypt_AES_CTR(private_key: bytes, nonce: bytes, ciphertext: bytes, num_iter: int = 250_000):
    encrypt_key = derive_encryption_key(private_key, count = num_iter)
    aes_cipher = Crypto.Cipher.AES.new(encrypt_key, Crypto.Cipher.AES.MODE_CTR, nonce=nonce)
    return aes_cipher.decrypt(ciphertext)

def _encrypt_AES_CTR_with_nonce(private_key: bytes, plaintext: bytes, nonce: bytes, num_iter: int = 250_000):
    """Version that accepts a specific nonce (for testing only!)"""
    encrypt_key = derive_encryption_key(private_key, count = num_iter)
    aes_cipher = Crypto.Cipher.AES.new(encrypt_key, Crypto.Cipher.AES.MODE_CTR, nonce=nonce)
    cipher_text = aes_cipher.encrypt(plaintext)
    return cipher_text

#######################################
# Helper functions for data packaging #
#######################################

def stream_data(mode: str, data: NDArray[np.uint8]):
    """Partition data into streams based on mode."""
    assert len(mode) == 2, "Mode must consistent of a letter and a number"
    mode_letter = mode[0].upper()
    num_streams = int(mode[1])
    num_datapoints = data.shape[0]
    remainder = (num_streams - (num_datapoints % num_streams)) % num_streams
    mod_data = np.concatenate((data,np.zeros(remainder, dtype=np.uint8))) if remainder > 0 else data
    match mode_letter:
        case 'E':
            return sEq_data(num_streams, mod_data)
        case 'K':
            return sKip_data(num_streams, mod_data)
        case _:
            raise ValueError(f"Unknown mode: {mode_letter}. Use 'S' for sequential or 'K' for skipping.")
    

def sKip_data(num_streams: int, data: NDArray[np.uint8]):
    """ Generate data-streams by skipping data points."""
    stream_length = data.shape[0] // num_streams
    split_data = np.ascontiguousarray(np.reshape(data, (num_streams, stream_length), order = 'F'))
    return split_data

def sEq_data(num_streams: int, data: NDArray[np.uint8]):
    """ Generate data-streams by splitting data sequentially."""
    stream_length = data.shape[0] // num_streams
    split_data = np.ascontiguousarray(np.reshape(data, (num_streams, stream_length), order = 'C'))
    return split_data

def recombine_data(mode: str, data: list[NDArray[np.uint8]]):
    """Recombine data streams into a single array."""
    assert len(mode) == 2, "Mode must consistent of a letter and a number"
    mode_letter = mode[0].upper()
    num_streams = int(mode[1])
    assert num_streams == len(data), f"Expected {num_streams} streams, got {len(data)}"
    num_datapoints = data[0].shape[0]
    assert all(stream.shape[0] == num_datapoints for stream in data), "All streams must have the same number of data points"
    data_array = np.vstack(data)
    match mode_letter:
        case 'E':
            return rEq_data(num_streams, data_array)
        case 'K':
            return rKip_data(num_streams, data_array)
        case _:
            raise ValueError(f"Unknown mode: {mode_letter}. Use 'S' for sequential or 'K' for skipping.")

def rEq_data(num_streams: int, data: NDArray[np.uint8]):
    """Recombine data streams by stacking them sequentially."""
    assert data.shape[0] % num_streams == 0, "Data length must be divisible by number of streams"
    stream_length = data.shape[1]
    recombined_data = np.ascontiguousarray(np.reshape(data, (num_streams * stream_length,), order = 'C'))
    return recombined_data

def rKip_data(num_streams: int, data: NDArray[np.uint8]):
    """Recombine data streams by stacking them with skips."""
    assert data.shape[0] % num_streams == 0, "Data length must be divisible by number of streams"
    stream_length = data.shape[1]
    recombined_data = np.ascontiguousarray(np.reshape(data, (num_streams * stream_length,), order = 'F'))
    return recombined_data

########################################
# Helper functions for data sanitation #
########################################

def calculate_padding_length(current_len: int) -> int:
    """
    Calculate how many bytes need to be appended so that the total length
    is both even and divisible by 3.
    
    Args:
        current_len (int): Current length of the packet in bytes.
    
    Returns:
        int: Number of padding bytes required.
    """
    # Start with no padding and increment until condition is met
    padding = 0
    while True:
        new_len = current_len + padding
        if new_len % 2 == 0 and new_len % 3 == 0:
            return padding
        padding += 1

def generate_padding_bytes(padding_len: int) -> NDArray[np.uint8]:
    """
    Generate a numpy array of cryptographically random bytes.
    
    Args:
        padding_len (int): Number of random bytes to generate.
    
    Returns:
        NDArray[np.uint8]: Array of random padding bytes.
    """
    if padding_len == 0:
        return np.array([], dtype=np.uint8)
    return np.frombuffer(os.urandom(padding_len), dtype=np.uint8)