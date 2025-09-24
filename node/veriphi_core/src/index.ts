import assert from 'node:assert/strict';
import * as utils from './utils';
import { randomBytes } from 'crypto';
import { decryptAESCTR, decryptAESGCM } from './utils';

import fs from 'node:fs';
import path from 'node:path';

const loadNativeBinding = (): any => {
    const searchRoots: string[] = [];
    let currentDir = __dirname;
    for (let i = 0; i < 6; i += 1) {
        searchRoots.push(currentDir);
        const parent = path.dirname(currentDir);
        if (parent === currentDir) {
            break;
        }
        currentDir = parent;
    }

    const candidates = searchRoots.flatMap((root) => [
        path.join(root, 'veriphi-core-node', 'index.node'),
        path.join(root, 'node_modules', '@veriphi', 'veriphi-core-node', 'index.node')
    ]);

    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) {
            return require(candidate);
        }
    }

    throw new Error(`Failed to locate native binding. Candidates checked: ${candidates.join(', ')}`);
};

const vc = loadNativeBinding();

/**
 * Represents a structured packet containing keys, identity, and mode metadata.
 */
export interface PacketDict {
    /** Public key associated with the packet */
    publicKey: Uint8Array;
    /** Private key associated with the packet */
    privateKey: Uint8Array;
    /** Raw packet data */
    packet: Uint8Array;
    /** Mode identifier (string) */
    mode: string;
    /** Identity index of the packet (must be unique within a set) */
    identity: number;
    /** Optional de-obfuscated packet after processing */
    deobfPacket?: Uint8Array;
}

/**
 * Represents an embedding that couples data with associated keys and identity.
 */
export interface EmbeddingDict {
    /** Embedded packet data */
    embedding: Uint8Array;
    /** Private key associated with the embedding */
    privateKey: Uint8Array;
    /** Public key associated with the embedding */
    publicKey: Uint8Array;
    /** Identity index for the embedding */
    identity: number;
}

/**
 * Utility class providing common key-generation and validation methods.
 */
export class Utils {
  partyId: string;
  /**
   * Create a new utility instance for a given party.
   * @param partyId Unique identifier for the party.
   */
  constructor(partyId: string) {
    this.partyId = partyId;
  }

  /**
   * Generates a private key for a specific purpose using a seed.
   * @param purpose Purpose of the key (e.g., "publicKey").
   * @param seed 32-byte seed buffer.
   * @returns Generated private key as a Buffer.
   * @throws If the seed length is not 32 bytes or key validation fails.
   */
  genPrivateKey(purpose: string, seed: Buffer): Buffer {
    assert(seed.length === 32, 'Mode must consist of a letter and a number');
    const key = vc.genKey(this.partyId, purpose, seed);
    this.checkKey(key);
    return key;
  }

  /**
   * Validates that a key contains only unique values.
   * @param key Buffer representing the key.
   * @throws If the key contains duplicate elements.
   */
  checkKey(key: Buffer): void {
    const unique = new Set(key);
    if (unique.size !== key.length) {
      throw new Error('Invalid key: key contains duplicate elements');
    }
  }
}

/**
 * Node responsible for setup operations like generating public keys,
 * obfuscating/encrypting data, and packaging payloads.
 */
export class SetupNode extends Utils {
    constructor(partyId: string) {
        super(partyId);
    }

    /**
     * Generates a public key from a 32-byte seed.
     * @param seed 32-byte buffer seed.
     * @returns Generated public key as a Buffer.
     * @throws If seed is not 32 bytes or key validation fails.
     */
    genPublicKey(seed: Buffer): Buffer {
        if (seed.length !== 32) {
        throw new Error('Seed must be exactly 32 bytes');
        }
        const key = this.genPrivateKey('publicKey', seed);
        this.checkKey(key);
        return key;
    }

    /**
     * Prepares conditional values using bounds and a private key.
     * @param lowBound Lower bound for condition.
     * @param highBound Upper bound for condition.
     * @param privateKey Private key buffer.
     * @returns Tuple of [lowValue, highValue].
     */
    implementConditions(lowBound: number, highBound: number, privateKey: Buffer): [number, number] {
        const [lowValue, highValue] = vc.prepCondition(lowBound, highBound, privateKey);
        return [lowValue, highValue];
    }

    /**
     * Tests whether a value satisfies conditions under a private key.
     * @param lowBound Lower bound.
     * @param highBound Upper bound.
     * @param testValue Value to test.
     * @param privateKey Private key buffer.
     * @returns Resulting branch integer from condition hash.
     */
    _testConditions(
        lowBound: number,
        highBound: number,
        testValue: number,
        privateKey: Buffer
    ): number {
        const [lowValue, highValue] = vc.prepCondition(lowBound, highBound, privateKey);
        return vc.condHashBranch(lowValue, highValue, testValue, privateKey);
    }

    /**
     * Obfuscates packet data with conditions and returns its transformed version.
     * @param packet Packet buffer.
     * @param privateKey Private key buffer.
     * @param lowBound Lower bound.
     * @param highBound Upper bound.
     * @param testValue Value to test.
     * @returns Tuple of [obfuscated packet buffer, chunk size].
     */
    obfuscateData(
        packet: Buffer,
        privateKey: Buffer,
        lowBound: number,
        highBound: number,
        testValue: number
    ): [Buffer, number] {
        const chunkSize = vc.getChunkSize(packet);
        const invPacket = vc.condInvolutePacket(packet, privateKey, chunkSize, lowBound, highBound, testValue);
        return [invPacket, chunkSize];
    }

    /**
     * Encrypts data using AES-CTR mode.
     * @param data Data buffer to encrypt.
     * @param privateKey Private key buffer.
     * @param numIter Number of iterations (default 250,000).
     * @returns Tuple of [ciphertext, nonce].
     */
    encryptData(data: Buffer, privateKey: Buffer, numIter = 250_000): [Buffer, Buffer] {
        return utils.encryptAESCTR(privateKey, data, numIter);
    }

    /**
     * Encrypts data using AES-GCM mode (authenticated encryption).
     * @param data Data buffer to encrypt.
     * @param privateKey Private key buffer.
     * @param numIter Number of iterations (default 250,000).
     * @returns Tuple of [ciphertext, metadata (nonce + tag)].
     */
    _encryptData(data: Buffer, privateKey: Buffer, numIter = 250_000): [Buffer, Buffer] {
        // GCM returns ciphertext, tag, nonce
        const [ciphertext, tag, nonce] = utils.encryptAESGCM(privateKey, data, numIter);
        const metadata = Buffer.concat([nonce, tag]);
        return [ciphertext, metadata];
    }

    /**
     * Packages packet data, public key, mode, and identity into a serialized buffer.
     * @param packet Raw packet buffer.
     * @param publicKey Public key buffer.
     * @param mode Mode string.
     * @param identity Identity number.
     * @returns Serialized package buffer.
     */
    packageData(packet: Buffer, publicKey: Buffer, mode: string, identity: number): Buffer {
        const modeBuf = Buffer.from(mode, 'utf-8');

        // Helper to pack UInt64LE (like struct.pack('<Q', val))
        function packUInt64LE(val: number): Buffer {
            const buf = Buffer.alloc(8);
            buf.writeBigUInt64LE(BigInt(val));
            return buf;
        }

        const payload = Buffer.concat([
            packUInt64LE(publicKey.length),
            publicKey,
            packUInt64LE(packet.length),
            packet,
            packUInt64LE(modeBuf.length),
            modeBuf,
            packUInt64LE(identity)        
        ]);
        const totalSizeHeader = packUInt64LE(payload.length);
        return Buffer.concat([totalSizeHeader, payload]);
    }
}

/**
 * Node responsible for embedding, encrypting, cycling keys, and packaging/unpackaging embeddings.
 */
export class EncryptNode extends Utils {
    constructor(partyId: string) {
        super(partyId);
    }
    
    /**
     * Encrypts a packet into an embedding, obfuscates it, and returns metadata.
     * @param packet Packet buffer to encrypt.
     * @param privateKey Private key buffer.
     * @param publicKey Public key buffer.
     * @param mode Mode string.
     * @param identity Identity number.
     * @returns Embedding dictionary with encrypted embedding.
     */
    encryptData(
        packet: Buffer,
        privateKey: Buffer,
        publicKey: Buffer,
        mode: string,
        identity: number,
    ): EmbeddingDict {
        if (!Buffer.isBuffer(packet)) {
            throw new Error('Packet must be a Buffer (uint8 data)');
        }
        const embedding = this._embedData(packet, privateKey, publicKey, mode, identity);
        const embeddingBuffer: Buffer = Buffer.from(embedding["embedding"]);
        const chunkSize: number = vc.getChunkSize(embeddingBuffer);
        const keyConcat = Buffer.concat([
        embedding["privateKey"],
        embedding["publicKey"]
        ]);

        const encrypted: Buffer = vc.involutePacket(embeddingBuffer, keyConcat, chunkSize);

        embedding["embedding"] = encrypted;

        return embedding;
    }
    
    /**
     * Performs the core embedding primitive and packages data into an embedding dictionary.
     * @param packet Packet buffer.
     * @param privateKey Private key buffer.
     * @param publicKey Public key buffer.
     * @param mode Mode string.
     * @param identity Identity number.
     * @returns Embedding dictionary.
     */
    _embedData(
        packet: Buffer,
        privateKey: Buffer,
        publicKey: Buffer,
        mode: string,
        identity: number,
    ): EmbeddingDict {
        if (!Buffer.isBuffer(packet)) {
            throw new Error('Packet must be a Buffer (uint8 data)');
        }
        const streamedData = utils.streamData(mode, packet);
        const embedding = vc.mapData(publicKey, privateKey, identity, streamedData);
        return {
            embedding: embedding,
            privateKey: privateKey,
            publicKey: publicKey,
            identity: identity
        }
    }

    /**
     * Rotates encrypted data from an old key to a new key whilst preserving validity.
     * @param encryptedData Encrypted buffer.
     * @param oldKey Old private key buffer.
     * @param newKey New private key buffer.
     * @param publicKey Public key buffer.
     * @returns Cycled encrypted buffer.
     */
    cycleKey(
        encryptedData: Buffer,
        oldKey: Buffer,
        newKey: Buffer,
        publicKey: Buffer
    ): Buffer {
        if (!Buffer.isBuffer(encryptedData)) {
            throw new Error('Encrypted data must be a Buffer (uint8 data)');
        }
        const chunkSize = vc.getChunkSize(encryptedData);

        const oldSalt = Buffer.concat([oldKey, publicKey]);
        const newSalt = Buffer.concat([newKey, publicKey]);
        const cycled = vc.cyclePacket(
            encryptedData,
            oldSalt,
            newSalt,
            oldKey,
            newKey,
            chunkSize
        );
        return cycled;
    }

    /**
     * Packages an embedding dictionary along with mode and identity into a serialized buffer.
     * @param embeddingDict Embedding dictionary.
     * @param mode Mode string.
     * @param identity Identity number.
     * @returns Serialized buffer package.
     */
    packageData( 
        embeddingDict: EmbeddingDict,
        mode: string,
        identity: number,
    ): Buffer {
        const packetBytes = embeddingDict.embedding;
        const privateKey = Buffer.from(embeddingDict.privateKey);
        const publicKey = Buffer.from(embeddingDict.publicKey);
        const modeBytes = Buffer.from(mode, 'utf-8');
        
        function lenHeader(len: number): Buffer {
            const buf = Buffer.alloc(8);
            buf.writeBigUInt64LE(BigInt(len), 0);
            return buf;
        }

        const payload = Buffer.concat([
            lenHeader(publicKey.length),
            publicKey,
            lenHeader(privateKey.length),
            privateKey,
            lenHeader(packetBytes.length),
            packetBytes,

            lenHeader(modeBytes.length),
            modeBytes,
            lenHeader(identity),
        ]);

        const totalSizeHeader = Buffer.alloc(8);
        totalSizeHeader.writeBigUInt64LE(BigInt(payload.length), 0);

        return Buffer.concat([totalSizeHeader, payload]);
    }

     /**
     * Unpackages serialized data from a setup node back into its components.
     * @param data Serialized buffer.
     * @returns Tuple [publicKey, packet, mode, identity].
     */
    unpackageData(data: Buffer): [Buffer, Buffer, string, number] {
        let offset = 8; // skip initial header (UInt64LE)

        // Helper to read UInt64LE from buffer (returns number)
        function readUInt64LE(buf: Buffer, off: number): number {
            // Buffer has readBigUInt64LE, convert safely to Number
            const bigVal = buf.readBigUInt64LE(off);
            const numVal = Number(bigVal);
            if (numVal > Number.MAX_SAFE_INTEGER) {
            throw new Error('Size exceeds safe integer range');
            }
            return numVal;
        }

        // Extract publicKey
        const pubKeySize = readUInt64LE(data, offset);
        offset += 8;
        const publicKey = data.subarray(offset, offset + pubKeySize);
        offset += pubKeySize;

        // Extract packet
        const packetSize = readUInt64LE(data, offset);
        offset += 8;
        const packetBytes = data.subarray(offset, offset + packetSize);
        offset += packetSize;
        

        // Extract mode
        const modeSize = readUInt64LE(data, offset);
        offset += 8;
        const mode = data.subarray(offset, offset + modeSize).toString('utf-8');
        offset += modeSize;

        // Extract label
        const identity = readUInt64LE(data, offset);
        return [publicKey, packetBytes, mode, identity];
    }

    /**
     * Unpacks encrypted serialized data from an encryptNode into a PacketDict for inspection/cycling.
     * @param data Serialized buffer.
     * @returns Packet dictionary with keys, packet, mode, and identity.
     */
    _unpackEncryptedData(data: Buffer): PacketDict {
        let offset = 8; // Skip total size header

        function readLength(): number {
            const len = Number(data.readBigUInt64LE(offset));
            offset += 8;
            return len;
        }

        // Extract a Buffer slice of given length
        function readBuffer(len: number): Buffer {
            const buf = data.subarray(offset, offset + len);
            offset += len;
            return buf;
        }

        // Extract publicKey
        const pubKeySize = readLength();
        const publicKey = readBuffer(pubKeySize);

        // Extract privateKey
        const privKeySize = readLength();
        const privateKey = readBuffer(privKeySize);

        // Extract packet
        const packetSize = readLength();
        const packetBuffer = readBuffer(packetSize);
        const packet = new Uint8Array(packetBuffer.buffer, packetBuffer.byteOffset, packetBuffer.byteLength);

        // Extract mode string
        const modeSize = readLength();
        const mode = data.subarray(offset, offset + modeSize).toString('utf8');
        offset += modeSize;

        // Extract label string
        
        const identity = Number(data.readBigUInt64LE(offset));
        return {
            publicKey: publicKey,
            privateKey: privateKey,
            packet: packet,
            mode: mode,
            identity: identity
        };
    }
}

/**
 * Node responsible for decrypting, recovering, and reconstructing original data from packets.
 */
export class DecryptNode extends Utils {
    constructor(partyId: string) {
        super(partyId);
    }
    
    /**
     * Collects multiple serialized packet buffers into a list of PacketDicts.
     * @param args List of serialized packet buffers.
     * @returns List of packet dictionaries.
     */
    collectPackets(...args: Buffer[]): PacketDict[] {
        return args.map(arg => this.unpackageData(arg));
    }

    /**
     * Unpackages serialized buffer into a PacketDict structure.
     * @param data Serialized buffer.
     * @returns Packet dictionary.
     */
    unpackageData(data: Buffer): PacketDict {
        let offset = 8; // Skip total size header

        const readLength = (): number => {
            const len = Number(data.readBigUInt64LE(offset));
            offset += 8;
            return len;
        };
        function readUInt64LE(buf: Buffer, off: number): number {
            // Buffer has readBigUInt64LE, convert safely to Number
            const bigVal = buf.readBigUInt64LE(off);
            const numVal = Number(bigVal);
            if (numVal > Number.MAX_SAFE_INTEGER) {
            throw new Error('Size exceeds safe integer range');
            }
            return numVal;
        }

        const readBuffer = (len: number): Buffer => {
        const buf = data.subarray(offset, offset + len);
        offset += len;
        return buf;
        };

        const pubKeySize = readLength();
        const publicKey = readBuffer(pubKeySize);

        const privKeySize = readLength();
        const privateKey = readBuffer(privKeySize);

        const packetSize = readLength();
        const packetBuffer = readBuffer(packetSize);
        const packet = new Uint8Array(packetBuffer.buffer, packetBuffer.byteOffset, packetBuffer.byteLength);

        const modeSize = readLength();
        const mode = data.subarray(offset, offset + modeSize).toString("utf8");
        offset += modeSize;

        const identity = readUInt64LE(data, offset);

        return {
            publicKey: publicKey,
            privateKey: privateKey,
            packet: packet,
            mode: mode,
            identity: identity
        };
    }

    /**
     * Recovers and de-obfuscates packet data from a list of PacketDicts.
     * @param packetList List of packet dictionaries.
     * @returns Augmented list with deobfuscated packets.
     */
    recoverPackets(packetList: PacketDict[]): PacketDict[] {
        const augList: PacketDict[] = [];

        for (const packet of packetList) {
            const privKey = new Uint8Array(packet.privateKey);
            const pubKey = new Uint8Array(packet.publicKey);

            const combinedKey = new Uint8Array(privKey.length + pubKey.length);
            combinedKey.set(privKey, 0);
            combinedKey.set(pubKey, privKey.length);

            const embeddedData = Buffer.from(packet.packet.buffer, packet.packet.byteOffset, packet.packet.byteLength);

            const chunkSize = vc.getChunkSize(embeddedData);

            const deobfBuffer = vc.involutePacket(
                embeddedData,
                Buffer.from(combinedKey.buffer),
                chunkSize
            );

            packet.deobfPacket = new Uint8Array(deobfBuffer.buffer, deobfBuffer.byteOffset, deobfBuffer.byteLength);
            packet.privateKey = privKey;
            packet.publicKey = pubKey;

            augList.push(packet);
        }
        return augList;
    }

    /**
     * Reconstructs original data streams from multiple packet dictionaries.
     * @param packetList List of packet dictionaries.
     * @returns Reconstructed data as a list of Uint8Arrays.
     * @throws If validation checks fail (modes, public key, identities).
     */
    reconstructData(packetList: PacketDict[]): Uint8Array[] {
        const numParties = packetList.length;

        // First check all parties have the same mode and public key
        const firstMode = packetList[0].mode;
        const firstPubKey = packetList[0].publicKey;
        for (let i = 1; i < numParties; i++) {
            if (packetList[i].mode !== firstMode) {
                throw new Error('All packets must have the same mode');
            }
            if (!Buffer.from(packetList[i].publicKey).equals(Buffer.from(firstPubKey))) {
                throw new Error('All packets must have the same public key');
            }
        }
        // Next check that all packets have deobfPacket
        for (let i = 0; i < numParties; i++) {
            if (!packetList[i].deobfPacket) {
                throw new Error('All packets must have deobfPacket populated. Call recoverPackets first.');
            }
        }
        /* Next check that all parties have a unique identity, and between all parties we count
        up from 0 to numParties-1 */
        const identitySet = new Set<number>();
        for (let i = 0; i < numParties; i++) {
            identitySet.add(packetList[i].identity);
        }
        
        if (identitySet.size !== numParties) {
            throw new Error('All packets must have a unique identity');
        }
        for (let i = 0; i < numParties; i++) {
            if (!identitySet.has(i)) {
                throw new Error('Identities must be sequential from 0 to numParties-1');
            }
        }
        const privateKeyArrays = new Array<Uint8Array>(numParties);
        const dataSequences = new Array<Uint8Array>(numParties);
        // Now go through all the parties and place their private keys and data in the right index
        for (let i = 0; i < numParties; i++) {
            const identity = packetList[i].identity;
            privateKeyArrays[identity] = packetList[i].privateKey;
            dataSequences[identity] = packetList[i].deobfPacket as Uint8Array;
        }

        const recovData = vc.invData(firstPubKey, privateKeyArrays, dataSequences);
        return recovData;   
    }

    /**
     * Decrypts ciphertext using AES-CTR mode.
     * @param ciphertext Encrypted data as Uint8Array.
     * @param nonce Nonce buffer.
     * @param privateKey Private key buffer.
     * @param numIter Number of iterations (default 250,000).
     * @returns Decrypted plaintext as Uint8Array.
     */
    decryptData(
        ciphertext: Uint8Array,
        nonce: Uint8Array,
        privateKey: Uint8Array,
        numIter = 250_000
    ): Uint8Array {
        return decryptAESCTR(Buffer.from(privateKey), Buffer.from(nonce), Buffer.from(ciphertext), numIter);
    }

    /**
     * Decrypts ciphertext using AES-GCM mode (authenticated encryption).
     * @param ciphertext Encrypted data as Uint8Array.
     * @param metadata Metadata buffer containing nonce + tag.
     * @param privateKey Private key buffer.
     * @param numIter Number of iterations (default 250,000).
     * @returns Decrypted plaintext as Uint8Array.
     */
    _decryptData(
        ciphertext: Uint8Array,
        metadata: Uint8Array,
        privateKey: Uint8Array,
        numIter = 250_000
    ): Uint8Array {
        const nonce = metadata.slice(0, 12);
        const tag = metadata.slice(12);
        return decryptAESGCM(Buffer.from(privateKey), Buffer.from(nonce), Buffer.from(ciphertext), Buffer.from(tag), numIter);
    }

    /**
     * Reassembles a list of data streams into the final data.
     * @param streamList List of data chunks as Uint8Arrays.
     * @param mode Mode string.
     * @returns Recombined data as Uint8Array.
     */
    reassembleData(streamList: Uint8Array[], mode: string): Uint8Array {
        const buffers = streamList.map(s => Buffer.from(s));
        return utils.recombineData(mode, buffers); 
    }

    /**
     * Obfuscates data based on key and conditional values, for deobfuscation, but using involutive approach, so same name.
     * @param packet Data packet as Uint8Array.
     * @param privateKey Private key buffer.
     * @param lowBound Lower bound.
     * @param highBound Upper bound.
     * @param testValue Value to test (float).
     * @returns Tuple of [obfuscated data, chunk size].
     */
    obfuscateData(
        packet: Uint8Array,
        privateKey: Buffer,
        lowBound: number,
        highBound: number,
        testValue: number // TS equivalent of np.float32
        ): [Uint8Array, number] {
        const saltArray = new Uint8Array(privateKey); // frombuffer(privateKey, dtype=np.uint8)
        const chunkSize = vc.getChunkSize(packet);
        const invPacket = vc.condInvolutePacket(packet, saltArray, chunkSize, lowBound, highBound, testValue);
        return [new Uint8Array(invPacket), chunkSize];
    }

}

export function setupNode(
    data: Uint8Array,
    condLow: number,
    condHigh: number,
    encrypt = false
): [Record< string, any>, Record< string, any> ]
{
    const setupNode = new SetupNode('Authoriser');
    const seed = Buffer.from(randomBytes(32));
    const publicKey = setupNode.genPublicKey(seed);
    const privateKey = setupNode.genPrivateKey('obf_privateKey', seed);
    let encrypted: Buffer;
    let nonce: Buffer;
    if (encrypt) {
        [encrypted, nonce] = setupNode.encryptData(Buffer.from(data), privateKey);
    } else {
        encrypted = Buffer.from(data);
        nonce = Buffer.alloc(0);
    }

    const testVal = (condLow + condHigh) / 2;
    const [lowVal, highVal] = setupNode.implementConditions(condLow, condHigh, privateKey);
    const [obfData] = setupNode.obfuscateData(encrypted, privateKey, lowVal, highVal, testVal);

    const publicData: Record<string, any> = { data: obfData, key: publicKey };
    const privateData: Record<string, any> = { key: privateKey, low_val: lowVal, high_val: highVal , nonce: nonce};

    return [publicData, privateData];
}

export function distributeData(
    publicData: Record<string, any>,
    streamMode: string,
    numParties: number
    ): Buffer[] {
    const setupNode = new SetupNode('');
    const mode = streamMode + numParties;

    const packets: Buffer[] = [];
    for (let i = 0; i < numParties; i++) {
        const packet = setupNode.packageData(
        publicData.data,
        publicData.key,
        mode,
        i
        );
        packets.push(packet);
    }
    return packets;
}

export function encryptNode(
    packet: Buffer,
    nodeLabel = 'encryption_node'
    ): Buffer {
    const encryptNode = new EncryptNode(nodeLabel);
    const [publicKey, packetData, mode, identity ] = encryptNode.unpackageData(packet);
    const privateKey = encryptNode.genPrivateKey(
        'label_privateKey',
        randomBytes(32)
    );
    const encrypted = encryptNode.encryptData(Buffer.from(packetData), privateKey, publicKey, mode, identity);
    return encryptNode.packageData(encrypted, mode, identity);
}

export function cycleKey(
      encryptedPacket: Buffer,
      nodeLabel = 'encryption_node'
    ): Buffer {
    const encryptNode = new EncryptNode(nodeLabel);
    const encryptedData = encryptNode._unpackEncryptedData(encryptedPacket);
    const newPrivateKey = encryptNode.genPrivateKey(
        'cycled_key',
        randomBytes(32)
    );

    const cycledData = encryptNode.cycleKey(
        Buffer.from(encryptedData.packet),
        Buffer.from(encryptedData.privateKey),
        newPrivateKey,
        Buffer.from(encryptedData.publicKey)
    );

    const embeddingDict: EmbeddingDict = {
        embedding: cycledData,
        privateKey: new Uint8Array(newPrivateKey),
        publicKey: new Uint8Array(encryptedData.publicKey),
        identity: encryptedData.identity,
    };

    return encryptNode.packageData(embeddingDict, encryptedData.mode, encryptedData.identity);
}

export function decryptNode(
    privateData: Record<string, any>,
    testValue: number,
    encrypt: boolean,
    ...args: Buffer[]
    ): Uint8Array {
    const veriphier = new DecryptNode('Veriphier');
    const partyData = veriphier.collectPackets(...args);
    const partyDataRecov = veriphier.recoverPackets(partyData);
    const streamList = veriphier.reconstructData(partyDataRecov);
    const reconstructed = veriphier.reassembleData(streamList, partyData[0].mode);
    const [recovered] = veriphier.obfuscateData(
        reconstructed,
        privateData.key,
        privateData.low_val,
        privateData.high_val,
        testValue
    );
    if (encrypt) {
        return veriphier.decryptData(
            recovered,
            privateData.nonce,
            privateData.key
        );
    }
    return recovered;
}
