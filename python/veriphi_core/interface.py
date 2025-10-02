import veriphi_core as vc
import numpy as np
import secrets
import struct
from numpy.typing import NDArray
from . import utils as utils

class Utils:
    """
    Utility class for cryptographic key generation and validation.
    
    This class provides methods for generating private keys, validating keys,
    and serves as a base class for data packaging operations.
    
    Attributes:
        party_id (str): Identifier for the party using this utility instance.
    """
    def __init__(self, party_id:str) -> None:
        """
        Initialize the Utils instance with a party identifier.
        
        Args:
            party_id (str): Unique identifier for the party.
        """
        self.party_id = party_id

    def gen_private_key(self, purpose: str, seed: NDArray[np.uint8]) -> bytes:
        """
        Generate a private key for a specific purpose using a cryptographic seed.
        
        Args:
            purpose (str): The intended purpose or context for the key generation.
            seed (NDArray[np.uint8]): A 32-byte seed used for key generation.
                                     Must be exactly 32 bytes in length.
        
        Returns:
            bytes: The generated private key as 32 bytes.
        
        Raises:
            AssertionError: If the seed is not exactly 32 bytes long.
            ValueError: If the generated key contains duplicate elements.
        """

        assert len(seed) == 32, "Seed must be exactly 32 bytes"
        key = vc.gen_key(self.party_id, purpose, seed)
        self.check_key(key)
        return key
    
    def check_key(self,key: bytes) -> None:
        """
        Validate that a cryptographic key contains no duplicate elements.
        
        Args:
            key (bytes): The key to validate as bytes.
        
        Raises:
            ValueError: If the key contains duplicate elements, making it invalid
                       for cryptographic purposes.
        """
        key_list = list(key)
        if len(key_list) != len(np.unique(key_list)):
            raise ValueError("Invalid key: key contains duplicate elements")

    def package_data(self):
        raise NotImplementedError("This method should be implemented by subclasses")

class SetupNode(Utils):
    """
    Node class for setting up cryptographic data and conditions.
    
    This class extends Utils to provide functionality for generating public keys,
    implementing and testing conditional cryptographic operations, obfuscating data
    based on conditions, and encrypting data with AES. It serves as the initial
    setup phase in a multi-node cryptographic system.
    
    Inherits from:
        Utils: Base utility class for cryptographic operations.
    """
    def __init__(self, party_id: str) -> None:
        """
        Initialize the SetupNode with a party identifier.
        
        Args:
            party_id (str): Unique identifier for the party.
        """
        super().__init__(party_id)

    def gen_public_key(self,seed) -> bytes:
        """
        Generate a public key using a cryptographic seed.
        
        Creates a public key by calling the inherited gen_private_key method
        with "public_key" as the purpose, then validates the generated key.
        
        Args:
            seed (NDArray[np.uint8]): A 32-byte seed used for key generation.
                                     Must be exactly 32 bytes in length.
        
        Returns:
            bytes: The generated public key.
        
        Raises:
            AssertionError: If the seed is not exactly 32 bytes long.
            ValueError: If the generated key contains duplicate elements.
        """
        key = self.gen_private_key("public_key",seed)
        self.check_key(key)
        return key
    
    def implement_conditions(self,low_bound: float, high_bound: float, private_key: bytes) -> tuple[int, int]:
        """
        Implement cryptographic conditions based on boundary values and a private key.
        
        Converts floating-point boundary conditions into integer values that can
        be used in conditional cryptographic operations.
        
        Args:
            low_bound (float): The lower boundary condition.
            high_bound (float): The upper boundary condition.
            private_key (bytes): The private key used for condition preparation.
        
        Returns:
            tuple[int, int]: A tuple containing:
                - low_value (int): The processed lower boundary value
                - high_value (int): The processed upper boundary value
        """
        key_array = np.frombuffer(private_key,dtype=np.uint8)
        low_value, high_value = vc.prep_condition(low_bound, high_bound, key_array)
        return low_value, high_value
    
    def _test_conditions(self, low_bound: float, high_bound: float, test_value: float, private_key: bytes) -> int:
        """
        Test whether a value satisfies the cryptographic conditions.
        
        Internal method that evaluates if a test value falls within the
        specified bounds using conditional hashing with the private key.
        
        Args:
            low_bound (float): The lower boundary condition.
            high_bound (float): The upper boundary condition.
            test_value (float): The value to test against the conditions.
            private_key (bytes): The private key used for condition evaluation.
        
        Returns:
            int: One of two values, derived from the underlying code, 
                depending on whether the condition is met or not
        """
        key_array = np.frombuffer(private_key,dtype=np.uint8)
        low_value, high_value = vc.prep_condition(low_bound, high_bound, key_array)
        return vc.cond_hash_branch(low_value, high_value, test_value, key_array)

    def obfuscate_data(self,packet: NDArray[np.uint8], private_key: bytes, low_bound:int, high_bound: int, test_value:np.float32) -> tuple[NDArray[np.uint8], int, int]:
        """
        Obfuscate data packet based on conditional cryptographic parameters.
        
        Applies conditional obfuscation to the data packet using the private key
        as salt and the boundary conditions with a test value to determine the
        obfuscation strategy.
        
        Args:
            packet (NDArray[np.uint8]): The data packet to obfuscate as numpy array.
            private_key (bytes): The private key used as cryptographic salt.
            low_bound (int): The lower boundary condition for obfuscation.
            high_bound (int): The upper boundary condition for obfuscation.
            test_value (np.float32): The test value that influences obfuscation method.
        
        Returns:
            tuple[NDArray[np.uint8], int]: A tuple containing:
                - obfuscated_packet (NDArray[np.uint8]): The obfuscated data as numpy array
                - chunk_size (int): The chunk size used in obfuscation
        """
        salt_array   = np.frombuffer(private_key, dtype=np.uint8)
        padding_len = utils.calculate_padding_length(len(packet))
        if padding_len > 0:
            padding_bytes = utils.generate_padding_bytes(padding_len)
            packet = np.concatenate((packet, padding_bytes))
        chunk_size = vc.get_chunk_size(packet)
        inv_packet = vc.cond_involute_packet(packet, salt_array, chunk_size, low_bound, high_bound, test_value)
        return np.frombuffer(inv_packet,dtype=np.uint8), chunk_size, padding_len

    def encrypt_data(self, data: bytes, private_key: bytes, num_iter = 250_000) -> tuple[bytes, bytes]:
        """
        Encrypt data using AES-CTR mode with key derivation.
        
        Encrypts the provided data using AES in Counter (CTR) mode with
        key derivation based on the specified number of iterations.
        
        Args:
            data (bytes): The data to encrypt.
            private_key (bytes): The private key used for encryption.
            num_iter (int, optional): Number of iterations for key derivation.
                                    Defaults to 250,000.
        
        Returns:
            tuple[bytes, bytes]: A tuple containing:
                - ciphertext (bytes): The encrypted data
                - nonce (bytes): The nonce used for encryption
        """
        ciphertext, nonce = utils.encrypt_AES_CTR(private_key, data, num_iter = num_iter)
        return ciphertext, nonce
    
    def _encrypt_data(self, data: bytes, private_key: bytes, num_iter = 250_000) -> tuple[bytes, bytes]:
        """
        Encrypt data using AES-GCM mode with authentication.
        
        Internal method that encrypts data using AES in Galois/Counter Mode (GCM)
        which provides both encryption and authentication. Note that message 
        validation is not recommended in this cryptographic context.
        
        Args:
            data (bytes): The data to encrypt.
            private_key (bytes): The private key used for encryption.
            num_iter (int, optional): Number of iterations for key derivation.
                                    Defaults to 250,000.
        
        Returns:
            tuple[bytes, bytes]: A tuple containing:
                - ciphertext (bytes): The encrypted data
                - metadata (bytes): Combined nonce and authentication tag
        """
        # Using GCM mode, which comes with message validation which is not recommended in this context
        ciphertext, tag, nonce = utils.encrypt_AES_GCM(private_key, data, num_iter = num_iter)
        metadata = nonce + tag
        return ciphertext, metadata

    def package_data(self, packet: NDArray[np.uint8], public_key: bytes, mode: str, identity: int) -> bytes:
        """
        Package data with metadata for transmission from setup node.
        
        Combines the data packet, public key, mode, and label into a single
        binary package with size headers for transmission to other nodes.
        This packaging format is different from EncryptNode packaging and
        contains only the essential setup data.
        
        Args:
            packet (NDArray[np.uint8]): The data packet to package as numpy array.
            public_key (bytes): The public key to include in the package.
            mode (str): The processing mode identifier.
            identity (int): Identity number.
        
        Returns:
            bytes: The packaged data ready for transmission, including size headers.
        """
        packet_bytes = packet.tobytes()
        mode_byte    = mode.encode('utf-8')
        # And now package everything into bytes
        payload = (
            struct.pack('<Q', len(public_key)) + public_key +
            struct.pack('<Q', len(packet_bytes)) + packet_bytes +
            struct.pack('<Q', len(mode_byte)) + mode_byte +
            struct.pack('<Q', identity)
        )
    
        # Add total size header
        total_size_header = struct.pack('<Q', len(payload))
        
        return total_size_header + payload

class EncryptNode(Utils):
    """
    Node class for encrypting and processing cryptographic data.
    
    This class extends Utils to provide functionality for encrypting data,
    mapping data across multiple nodes, cycling encryption keys, and packaging
    encrypted data for transmission. It supports both 2-node and 3-node
    cryptographic operations.
    
    Inherits from:
        Utils: Base utility class for cryptographic operations.
    """
    def __init__(self, party_id: str) -> None:
        """
        Initialize the EncryptNode with a party identifier.
        
        Args:
            party_id (str): Unique identifier for the party.
        """
        super().__init__(party_id) 

    
    def encrypt_data(self, packet: NDArray[np.uint8], private_key: bytes, public_key: bytes, mode: str, identity: int) -> dict:
        """
        Encrypt data with public and private key, mode, and label, then obfuscate it.
        
        Args:
            packet (NDArray[np.uint8]): The data packet to encrypt as numpy array.
            private_key (bytes): The private key for encryption.
            public_key (bytes): The public key for encryption.
            mode (str): The encryption mode.
            identity (int): The node identity.
        
        Returns:
            dict: A dictionary containing the encrypted embedding with keys:
                - 'embedding': The encrypted data
                - 'chunk': The chunk size used for encryption
                - Other embedding metadata
        
        Raises:
            AssertionError: If packet is not a numpy array of uint8.
        """       
        assert isinstance(packet, np.ndarray) and packet.dtype == np.uint8, "Packet must be a numpy array of uint8"
        
        # Embed data into the packet
        embedding = self._embed_data(packet, private_key, public_key, mode, identity)
        embedding_array = np.frombuffer(embedding["embedding"], dtype=np.uint8)
        chunk_size = vc.get_chunk_size(embedding_array)
        encrypted = vc.involute_packet(embedding_array, np.concatenate([np.frombuffer(embedding["private_key"],dtype=np.uint8),
                                                                        np.frombuffer(embedding["public_key"],dtype=np.uint8)]), chunk_size)
        embedding["embedding"] = encrypted
        return embedding
      
    def _embed_data(self, packet: NDArray[np.uint8], private_key: bytes, public_key: bytes, mode: str, identity: int) -> dict:
        """
        Embed data into a packet with cryptographic keys and metadata.
        
        Internal method that streams the packet data and maps it using
        the provided keys and parameters.
        
        Args:
            packet (NDArray[np.uint8]): The data packet to embed.
            private_key (bytes): The private key for embedding.
            public_key (bytes): The public key for embedding.
            mode (str): The embedding mode.
            label (int): The class identifier.
        
        Returns:
            dict: The embedded data with metadata.
        
        Raises:
            AssertionError: If packet is not a numpy array of uint8.
        """
        assert isinstance(packet, np.ndarray) and packet.dtype == np.uint8, "Packet must be a numpy array of uint8"
        streamed_data = utils.stream_data(mode, packet)
        embedding = vc.map_data(np.frombuffer(public_key, dtype=np.uint8), np.frombuffer(private_key, dtype=np.uint8), identity, streamed_data)
        
        return {"embedding": embedding, "private_key": private_key, "public_key":public_key, "identity":identity}

    def cycle_key(self, encrypted_data: NDArray[np.uint8], old_key: bytes, new_key: bytes, public_key: bytes) -> NDArray[np.uint8]:
        """
        Cycle the encryption key for encrypted data.
        
        Replaces the old encryption key with a new one while maintaining
        the encrypted data structure.
        
        Args:
            encrypted_data (NDArray[np.uint8]): The encrypted data as numpy array.
            old_key (bytes): The current encryption key to replace.
            new_key (bytes): The new encryption key to use.
            public_key (bytes): The public key used to construct the salt for obfuscation
        
        Returns:
            NDArray[np.uint8]: The data encrypted with the new key.
        
        Raises:
            AssertionError: If encrypted_data is not a numpy array of uint8.
        """
        assert isinstance(encrypted_data, np.ndarray) and encrypted_data.dtype == np.uint8, "Encrypted data must be a numpy array of uint8"
        chunk_size = vc.get_chunk_size(encrypted_data)
        old_salt = np.concatenate([np.frombuffer(old_key,dtype=np.uint8),np.frombuffer(public_key,dtype=np.uint8)])
        new_salt = np.concatenate([np.frombuffer(new_key,dtype=np.uint8),np.frombuffer(public_key,dtype=np.uint8)])
        old_key = np.frombuffer(old_key, dtype=np.uint8)
        new_key = np.frombuffer(new_key, dtype=np.uint8)
        cycled   = vc.cycle_packet(encrypted_data, old_salt, new_salt, old_key, new_key, chunk_size)
        return cycled

    def package_data(self, embedding_dict: dict, mode: str, identity: int) -> bytes:
        """
        Package encrypted data with metadata for transmission.
        
        Combines encrypted data, keys, chunk size, mode, and label into
        a single binary package suitable for network transmission.
        
        Args:
            embedding_dict (dict): Dictionary containing encryption data with keys:
                - 'embedding': The embedded data
                - 'private_key': The private key as numpy array
                - 'public_key': The public key as numpy array  
            mode (str): The encryption mode.
            identity (int): The node identifier.
        
        Returns:
            bytes: The packaged data ready for transmission, including size headers.
        """
        packet_bytes = embedding_dict["embedding"]
        private_key  = embedding_dict["private_key"]
        public_key   = embedding_dict["public_key"]
        mode_byte    = mode.encode('utf-8')
        # And now package everything into bytes
        payload = (
            struct.pack('<Q', len(public_key)) + public_key +
            struct.pack('<Q', len(private_key)) + private_key +
            struct.pack('<Q', len(packet_bytes)) + packet_bytes +
            struct.pack('<Q', len(mode_byte)) + mode_byte +
            struct.pack('<Q', identity)
        )
    
        # Add total size header
        total_size_header = struct.pack('<Q', len(payload))
        
        return total_size_header + payload

    def unpackage_data(self, data: bytes) -> tuple[bytes, NDArray[np.uint8], str, int]:
        """
        Unpackage encrypted data into its constituent components.
        
        Extracts the public key, packet data, mode, and label from a packaged
        data structure that was previously created by package_data.
        
        Args:
            data (bytes): The packaged data to unpack.
        
        Returns:
            tuple[bytes, NDArray[np.uint8], str, str]: A tuple containing:
                - public_key (bytes): The extracted public key
                - packet (NDArray[np.uint8]): The packet data as numpy array
                - mode (str): The encryption mode
                - identity (int): The node identifier
        """
        offset = 8
        
        # Extract public_key
        pub_key_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        public_key = data[offset:offset+pub_key_size]
        offset += pub_key_size
        
        # Extract packet
        packet_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        packet_bytes = data[offset:offset+packet_size]
        packet = np.frombuffer(packet_bytes, dtype=np.uint8)
        offset += packet_size
        
        # Extract mode
        mode_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        mode = data[offset:offset+mode_size].decode('utf-8')
        offset += mode_size
        
        # Extract label
        identity = struct.unpack('<Q', data[offset:offset+8])[0]
      
        return public_key, packet, mode, identity
        

    def _unpack_encrypted_data(self, data: bytes) -> dict:
        """
        Unpack encrypted data into a structured dictionary for inspection or key cycling.
        
        This internal method provides a convenient dictionary interface for accessing
        unpacked data components. It is used for data that was previously packaged
        by EncryptNode.package_data(), not for packets from setup nodes.
        
        Args:
            data (bytes): The packaged encrypted data to unpack.
        
        Returns:
            dict: A dictionary containing all unpacked components with keys:
                - 'public_key' (bytes): The public/synchronization key
                - 'private_key' (bytes): The private key used for encryption
                - 'packet' (NDArray[np.uint8]): The encrypted packet data
                - 'mode' (str): The encryption mode
                - 'identity' (int): The node identifier
        """
        offset = 8  # Skip the total size header

        # Extract public_key
        pub_key_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        public_key = data[offset:offset+pub_key_size]
        offset += pub_key_size

        # Extract private_key
        priv_key_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        private_key = data[offset:offset+priv_key_size]
        offset += priv_key_size

        # Extract packet
        packet_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        packet_bytes = data[offset:offset+packet_size]
        packet = np.frombuffer(packet_bytes, dtype=np.uint8)
        offset += packet_size

        # Extract mode
        mode_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        mode = data[offset:offset+mode_size].decode('utf-8')
        offset += mode_size

        # Extract label
        identity = struct.unpack('<Q', data[offset:offset+8])[0]
        data_dict = {
            "public_key": public_key,
            "private_key": private_key,
            "packet": packet,
            "mode": mode,
            "identity": identity
        }
        return data_dict

class DecryptNode(Utils):
    def __init__(self, party_id: str) -> None:
        """
        Initialize the DecryptNode with a party identifier.
        
        Args:
            party_id (str): Unique identifier for the party.
        """
        super().__init__(party_id) 

    def collect_packets(self, *args: dict) -> list[dict]:
        """
        Collects and unpacks 2 or 3 encrypted packet arguments.

        Args:
            *args (dict): Variable number of encrypted packet bytes (must be 2 or 3).

        Returns:
            list[dict]: A list of dictionaries with unpacked packet components.

        Raises:
            ValueError: If number of arguments is not 2 or 3.
        """
        if len(args) not in (2,3):
            raise ValueError("Expected 2 or 3 arguments, got {}".format(len(args)))
        return [self.unpackage_data(arg) for arg in args]

    def unpackage_data(self, data: bytes) -> dict:
        """
        Unpacks a single packet byte stream into its components.

        Args:
            data (bytes): Serialized packet data.

        Returns:
            dict: Dictionary containing public/private keys, packet, mode, and identity.
        """
        offset = 8  # Skip the total size header

        # Extract public_key
        pub_key_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        public_key = data[offset:offset+pub_key_size]
        offset += pub_key_size

        # Extract private_key
        priv_key_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        private_key = data[offset:offset+priv_key_size]
        offset += priv_key_size

        # Extract packet
        packet_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        packet_bytes = data[offset:offset+packet_size]
        packet = np.frombuffer(packet_bytes, dtype=np.uint8)
        offset += packet_size

        # Extract mode
        mode_size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        mode = data[offset:offset+mode_size].decode('utf-8')
        offset += mode_size

        # Extract identity
        identity = struct.unpack('<Q', data[offset:offset+8])[0]
        data_dict = {
            "public_key": public_key,
            "private_key": private_key,
            "packet": packet,
            "mode": mode,
            "identity": identity
        }
        return data_dict

    def recover_packets(self, packet_list: list[dict]) -> list[dict]:
        """
        Reconstructs and augments packet dictionaries with de-obfuscated data.

        Args:
            packet_list (list[dict]): List of unpacked packet dictionaries.

        Returns:
            list[dict]: Updated list with de-obfuscated packets and byte-converted keys.
        """
        aug_list = []
        for packet in packet_list:
            embedded_data = packet["packet"]
            chunk_size    = vc.get_chunk_size(embedded_data)
            recov_packet = vc.involute_packet(embedded_data, 
                                            np.concatenate([np.frombuffer(packet["private_key"], dtype=np.uint8),
                                                            np.frombuffer(packet["public_key"],dtype=np.uint8)]),
                                            chunk_size)
            packet["deobf_packet"] = np.frombuffer(recov_packet, dtype=np.uint8)
            packet["private_key"] = np.frombuffer(packet["private_key"], dtype=np.uint8)
            packet["public_key"] = np.frombuffer(packet["public_key"], dtype=np.uint8)
            aug_list.append(packet)
        return aug_list

    def reconstruct_data(self, packet_list: list[dict]) -> tuple[NDArray[np.uint8], ...]:
        """
        Reconstructs original data streams from packets based on number of parties.

        Args:
            packet_list (list[dict]): List of augmented packet dictionaries.

        Returns:
            tuple[NDArray[np.uint8], ...]: Reconstructed data streams (2 or 3 depending on input).
        """
        num_parties = len(packet_list)
        first_mode  = packet_list[0]["mode"]
        first_pub_key = packet_list[0]["public_key"]
        for i in range(1,num_parties):
            if packet_list[i]["mode"] != first_mode:
                raise ValueError("All packets must have the same mode")
            if (~np.all(packet_list[i]["public_key"] == first_pub_key)):
                raise ValueError("All packets must have the same public key")

        for i in range(num_parties):
            if "deobf_packet" not in packet_list[i]:
                raise ValueError("All packets must have the deobf_packet populated")
        
        identity_set = set()

        for i in range(num_parties):
            identity_set.add(packet_list[i]["identity"])

        if len(identity_set) != num_parties:
            raise ValueError("All packets must have a unique identity")

        for i in range(num_parties):
            if i not in identity_set:
                raise ValueError("Identities must be sequential from 0 to numParties-1")
        
        private_key_arrays: list[np.ndarray | None] = [None] * num_parties
        data_sequences: list[np.ndarray | None] = [None] * num_parties

        # Fill by identity index
        for i in range(num_parties):
            identity = packet_list[i]["identity"]

            # Convert to NumPy arrays (uint8). ascontiguousarray is handy for C/FFI.
            private_key_arrays[identity] = np.ascontiguousarray(packet_list[i]["private_key"], dtype=np.uint8)
            data_sequences[identity] = np.ascontiguousarray(packet_list[i]["deobf_packet"], dtype=np.uint8)
        return vc.inv_data(first_pub_key, private_key_arrays, data_sequences)
    
    def decrypt_data(self, ciphertext: bytes, nonce: bytes, private_key: bytes, num_iter: int = 250_000) -> bytes:
        """
        Decrypts ciphertext using AES-CTR mode.

        Args:
            ciphertext (bytes): The encrypted message.
            nonce (bytes): The nonce used during encryption.
            private_key (bytes): The key for decryption.
            num_iter (int, optional): Key stretching iterations. Defaults to 250,000.

        Returns:
            bytes: Decrypted plaintext.
        """
        return utils.decrypt_AES_CTR(private_key, nonce, ciphertext, num_iter = num_iter)
    
    def _decrypt_data(self, ciphertext: bytes, metadata: bytes, private_key: bytes, num_iter = 250_000) -> bytes:
        """
        Decrypts ciphertext using AES-GCM mode (authenticated encryption).

        Args:
            ciphertext (bytes): The encrypted message.
            metadata (bytes): Concatenated nonce (12 bytes) and tag.
            private_key (bytes): The decryption key.
            num_iter (int, optional): Key stretching iterations. Defaults to 250,000.

        Returns:
            bytes: Decrypted plaintext.
        """

        # Using GCM mode, which comes with message validation which is not recommended in this context
        nonce = metadata[:12]
        tag = metadata[12:]
        return utils.decrypt_AES_GCM(private_key, nonce, ciphertext, tag, num_iter = num_iter)

    def reassemble_data(self, stream_list: list[NDArray[np.uint8]], mode: str) -> NDArray[np.uint8]:
        """
        Reassembles original data from a list of byte streams.

        Args:
            stream_list (list[NDArray[np.uint8]]): List of data streams.
            mode (str): Mode used for recombination.

        Returns:
            NDArray[np.uint8]: Recombined original data.
        """
        stream_list_array = [np.frombuffer(stream, dtype=np.uint8) for stream in stream_list]
        data = utils.recombine_data(mode, stream_list_array)
        return data
    
    def obfuscate_data(self,packet: NDArray[np.uint8], private_key: bytes, low_bound:int, high_bound: int, test_value:np.float32) -> tuple[NDArray[np.uint8],int]:
        """
        Obfuscates data packet using a conditional involution transformation.

        Args:
            packet (NDArray[np.uint8]): The input data to obfuscate.
            private_key (bytes): Key used to derive salt for transformation.
            low_bound (int): Lower bound for transformation threshold.
            high_bound (int): Upper bound for transformation threshold.
            test_value (np.float32): Control value for conditional transformation.

        Returns:
            tuple: Transformed packet (NDArray) and chunk size used in transformation.
        """
        salt_array   = np.frombuffer(private_key, dtype=np.uint8)
        chunk_size = vc.get_chunk_size(packet)
        inv_packet = vc.cond_involute_packet(packet, salt_array, chunk_size, low_bound, high_bound, test_value)
        return np.frombuffer(inv_packet,dtype=np.uint8), chunk_size

def setup_node(data: NDArray[np.uint8],cond_low: np.float32, cond_high: np.float32, encrypt=False) -> tuple[dict, dict]:
    """
    Initializes a SetupNode, generates keys, and obfuscates input data based on conditional bounds.

    Args:
        data (NDArray[np.uint8]): Input data to obfuscate.
        cond_low (np.float32): Lower bound for obfuscation.
        cond_high (np.float32): Upper bound for obfuscation.
        encrypt (bool, optional): Whether to encrypt the data. Defaults to False.

    Returns:
        Tuple[dict, dict]: A tuple containing:
            - public_data: Dict with obfuscated data and public key.
            - private_data: Dict with private key and bound values for de-obfuscation.
    """
    setup_node = SetupNode(party_id = "Authoriser")
    seed = np.frombuffer(secrets.token_bytes(32), np.uint8)
    public_key = setup_node.gen_public_key(seed)
    private_key= setup_node.gen_private_key("obf_private_key", seed)
    if encrypt:
        encrypted, nonce = setup_node.encrypt_data(data,private_key)
        encrypted = np.frombuffer(encrypted,dtype=np.uint8)
    else:
        encrypted = data.copy()
        nonce = b""
    test_val = (cond_low + cond_high)/2
    low_val, high_val = setup_node.implement_conditions(cond_low, cond_high, private_key)
    obf_data,_, padding_len = setup_node.obfuscate_data(encrypted, private_key, low_val, high_val, test_val)
    public_data = {"data":obf_data, "key": public_key}
    private_data= {"key": private_key, "low_val":low_val, "high_val": high_val, "nonce": nonce, "padding":padding_len}
    return public_data, private_data

def distribute_data(public_data:dict, stream_mode:str, num_parties:int) -> list[bytes]:
    """
    Splits public data into multiple packets for distribution to parties.

    Args:
        public_data (dict): Dictionary with obfuscated data and public key.
        stream_mode (str): Base mode name for the data stream.
        num_parties (int): Number of parties to distribute data to.

    Returns:
        list[bytes]: List of serialized data packets for each party.
    """
    setup_node = SetupNode("")
    mode = stream_mode + str(num_parties)
    packets = []
    for i in range(num_parties):
        packets.append(setup_node.package_data(public_data["data"], 
                                                public_data["key"],mode=mode, identity=i))
    return packets

def encrypt_node(packet: dict, node_label: str =  "encryption_node") -> bytes:
    """
    Encrypts a packet using a generated private key and packages the result.

    Args:
        packet (dict): Dictionary containing public_key, data, mode, and label.
        node_label (str, optional): Label for the encryption node. Defaults to "encryption_node".

    Returns:
        bytes: Encrypted and serialized packet.
    """
    encrypt_node = EncryptNode(node_label)
    public_key, data_packet, mode, identity = encrypt_node.unpackage_data(packet)
    private_key = encrypt_node.gen_private_key("label" + "private_key", np.frombuffer(secrets.token_bytes(32), np.uint8))
    encrypted   = encrypt_node.encrypt_data(data_packet, private_key, public_key, mode, identity)
    return encrypt_node.package_data(encrypted, mode, identity)

def cycle_key(encrypted_packet: dict, node_label: str = "encryption_node") -> bytes:
    """
    Replaces the private key used in an encrypted packet and repackages the data.

    Args:
        encrypted_packet (dict): Previously encrypted packet.
        node_label (str, optional): Label for the encryption node. Defaults to "encryption_node".

    Returns:
        bytes: Re-encrypted packet with new private key.
    """
    encrypt_node = EncryptNode(node_label)
    encrypted_data = encrypt_node._unpack_encrypted_data(encrypted_packet)
    new_private_key = encrypt_node.gen_private_key("cycled_key",np.frombuffer(secrets.token_bytes(32),np.uint8))
    cycled_data = encrypt_node.cycle_key(encrypted_data["packet"],
                                         encrypted_data["private_key"],
                                         new_private_key, 
                                         encrypted_data["public_key"])
    
    embedding_dict = {"embedding":cycled_data, 
                      "private_key":new_private_key,
                      "public_key":encrypted_data["public_key"]}
    return encrypt_node.package_data(embedding_dict,encrypted_data["mode"], encrypted_data["identity"])

def decrypt_node(private_data:dict, test_value: np.float32, encrypt: bool, *args: dict):
    """
    Fully decrypts and reconstructs the original data from encrypted packets.

    Args:
        private_data (dict): Contains private key and bound values for de-obfuscation.
        test_value (np.float32): Conditional test value for de-obfuscation.
        encrypt (bool): Whether the original data was encrypted.
        *args (dict): Variable number of serialized encrypted packets (2 or 3 expected).

    Returns:
        NDArray[np.uint8]: Fully reconstructed and de-obfuscated data.
    """
    veriphier = DecryptNode("Veriphier")
    party_data = veriphier.collect_packets(*args)
    party_data_recov = veriphier.recover_packets(party_data)
    stream_list = veriphier.reconstruct_data(party_data_recov)
    reconstructed = veriphier.reassemble_data(stream_list, mode = party_data[0]["mode"])
    recovered,_ = veriphier.obfuscate_data(reconstructed, 
                                           private_data["key"], 
                                           private_data["low_val"], 
                                           private_data["high_val"], 
                                           test_value)
    if private_data["padding"] > 0:
        recovered = recovered[:-private_data["padding"]]
    if encrypt:
        return veriphier.decrypt_data(recovered.tobytes(), private_data["nonce"], private_data["key"])
    return recovered