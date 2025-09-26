import initWasm, * as vc from 'veriphi-core-wasm-pkg';

// Call this once before using any API (e.g. in your app entry)
export async function initVeriphiWasm(threads?: number) {
  // Loads the .wasm and initializes the JS glue
  await initWasm();
  // If you compiled with wasm-bindgen-rayon + threads + proper headers,
  // expose initThreads in the wasm lib and call it here.
  if (threads && (vc as any).initThreads) {
    await (vc as any).initThreads(threads);
  }
}
import * as utils from './utils.js';


const te = new TextEncoder();
const td = new TextDecoder();

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function utf8(str: string): Uint8Array {
  return te.encode(str);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function u64le(n: number | bigint): Uint8Array {
  const v = BigInt(n);
  const bytes = new Uint8Array(8);
  const dv = new DataView(bytes.buffer);
  dv.setBigUint64(0, v, true);
  return bytes;
}

function readU64leToNumber(buf: Uint8Array, offset: number): number {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const big = dv.getBigUint64(offset, true);
  const num = Number(big);
  if (num > Number.MAX_SAFE_INTEGER) {
    throw new Error('Size exceeds safe integer range');
  }
  return num;
}

function sliceBytes(buf: Uint8Array, offset: number, len: number): Uint8Array {
  return buf.subarray(offset, offset + len);
}

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
   * @param seed 32-byte seed array.
   * @returns Generated private key as a array.
   * @throws If the seed length is not 32 bytes or key validation fails.
   */
  genPrivateKey(purpose: string, seed: Uint8Array): Uint8Array {
    utils.assert(seed.length === 32, 'Mode must consist of a letter and a number');
    const key = vc.genKey(this.partyId, purpose, seed);
    this.checkKey(key);
    return key;
  }

  /**
   * Validates that a key contains only unique values.
   * @param key array representing the key.
   * @throws If the key contains duplicate elements.
   */
  checkKey(key: Uint8Array): void {
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
     * @param seed 32-byte array seed.
     * @returns Generated public key as a array.
     * @throws If seed is not 32 bytes or key validation fails.
     */
    genPublicKey(seed: Uint8Array): Uint8Array {
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
     * @param privateKey Private key array.
     * @returns Tuple of [lowValue, highValue].
     */
    implementConditions(lowBound: number, highBound: number, privateKey: Uint8Array): [number, number] {
        const [lowValue, highValue] = vc.prepCondition(lowBound, highBound, privateKey);
        return [lowValue, highValue];
    }

    /**
     * Tests whether a value satisfies conditions under a private key.
     * @param lowBound Lower bound.
     * @param highBound Upper bound.
     * @param testValue Value to test.
     * @param privateKey Private key Uint8Array.
     * @returns Resulting branch integer from condition hash.
     */
    _testConditions(
        lowBound: number,
        highBound: number,
        testValue: number,
        privateKey: Uint8Array
    ): BigInt {
        const [lowValue, highValue] = vc.prepCondition(lowBound, highBound, privateKey);
        return vc.condHashBranch(lowValue, highValue, testValue, privateKey);
    }

    /**
     * Obfuscates packet data with conditions and returns its transformed version.
     * @param packet Packet array.
     * @param privateKey Private key array.
     * @param lowBound Lower bound.
     * @param highBound Upper bound.
     * @param testValue Value to test.
     * @returns Tuple of [obfuscated packet array, chunk size].
     */
    obfuscateData(
        packet: Uint8Array,
        privateKey: Uint8Array,
        lowBound: bigint,
        highBound: bigint,
        testValue: number
    ): [Uint8Array, number, number] {
        const paddingLen = utils.calculatePaddingLength(packet.length);
        if (paddingLen > 0) {
            const padding = utils.generatePaddingBytes(paddingLen);
            const padded = new Uint8Array(packet.length + paddingLen);
            padded.set(packet, 0);
            padded.set(padding, packet.length);
            packet = padded;
        }
        const chunkSize = vc.getChunkSize(packet);
        const invPacket = vc.condInvolutePacket(packet, privateKey, chunkSize, lowBound, highBound, testValue);
        return [invPacket, chunkSize, paddingLen];
    }

    /**
     * Encrypts data using AES-CTR mode.
     * @param data Data array to encrypt.
     * @param privateKey Private key array.
     * @param numIter Number of iterations (default 250,000).
     * @returns Tuple of [ciphertext, nonce].
     */
    async encryptData(data: Uint8Array, privateKey: Uint8Array, numIter = 250_000): Promise<[Uint8Array, Uint8Array]> {
        return utils.encryptAESCTR(privateKey, data, numIter);
    }

    /**
     * Encrypts data using AES-GCM mode (authenticated encryption).
     * @param data Data array to encrypt.
     * @param privateKey Private key array.
     * @param numIter Number of iterations (default 250,000).
     * @returns Tuple of [ciphertext, metadata (nonce + tag)].
     */
    async _encryptData(data: Uint8Array, privateKey: Uint8Array, numIter = 250_000): Promise<[Uint8Array, Uint8Array]> {
        const [ciphertext, tag, nonce] = await utils.encryptAESGCM(privateKey, data, numIter);
        const metadata = concatBytes([nonce, tag]);
        return [ciphertext, metadata];
    }

    /**
     * Packages packet data, public key, mode, and identity into a serialized array.
     * @param packet Raw packet array.
     * @param publicKey Public key array.
     * @param mode Mode string.
     * @param identity Identity number.
     * @returns Serialized package array.
     */
    packageData(packet: Uint8Array, publicKey: Uint8Array, mode: string, identity: number): Uint8Array {
        const modeBuf = utf8(mode);

        const payload = concatBytes([
            u64le(publicKey.length), publicKey,
            u64le(packet.length),    packet,
            u64le(modeBuf.length),   modeBuf,
            u64le(identity),
        ]);

        const totalSizeHeader = u64le(payload.length);
        return concatBytes([totalSizeHeader, payload]);
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
     * @param packet Packet array to encrypt.
     * @param privateKey Private key array.
     * @param publicKey Public key array.
     * @param mode Mode string.
     * @param identity Identity number.
     * @returns Embedding dictionary with encrypted embedding.
     */
    encryptData(
        packet: Uint8Array,
        privateKey: Uint8Array,
        publicKey: Uint8Array,
        mode: string,
        identity: number,
    ): EmbeddingDict {
        if (! (packet instanceof Uint8Array)) {
            throw new Error('Packet must be a array (uint8 data)');
        }
        const embedding = this._embedData(packet, privateKey, publicKey, mode, identity);
        const embeddingBuffer: Uint8Array = embedding["embedding"];
        const chunkSize: number = vc.getChunkSize(embeddingBuffer);
        const keyConcat = concatBytes([embedding["privateKey"], embedding["publicKey"]]);
        const encrypted: Uint8Array = vc.involutePacket(embeddingBuffer, keyConcat, chunkSize);
        embedding["embedding"] = encrypted;
        return embedding;
    }
    
    /**
     * Performs the core embedding primitive and packages data into an embedding dictionary.
     * @param packet Packet array.
     * @param privateKey Private key Uint8Array.
     * @param publicKey Public key Uint8Array.
     * @param mode Mode string.
     * @param identity Identity number.
     * @returns Embedding dictionary.
     */
    _embedData(
        packet: Uint8Array,
        privateKey: Uint8Array,
        publicKey: Uint8Array,
        mode: string,
        identity: number,
    ): EmbeddingDict {
        if (!(packet instanceof Uint8Array)) {
            throw new Error('Packet must be a array (uint8 data)');
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
     * @param encryptedData Encrypted array.
     * @param oldKey Old private key array.
     * @param newKey New private key array.
     * @param publicKey Public key array.
     * @returns Cycled encrypted array.
     */
    cycleKey(
        encryptedData: Uint8Array,
        oldKey: Uint8Array,
        newKey: Uint8Array,
        publicKey: Uint8Array
        ): Uint8Array {
        const chunkSize = vc.getChunkSize(encryptedData);
        const oldSalt = concatBytes([oldKey, publicKey]);
        const newSalt = concatBytes([newKey, publicKey]);
        return vc.cyclePacket(
            encryptedData,
            oldSalt,
            newSalt,
            oldKey,
            newKey,
            chunkSize
        );
    }

    /**
     * Packages an embedding dictionary along with mode and identity into a serialized array.
     * @param embeddingDict Embedding dictionary.
     * @param mode Mode string.
     * @param identity Identity number.
     * @returns Serialized buffer package.
     */
    packageData(
        embeddingDict: EmbeddingDict,
        mode: string,
        identity: number,
        ): Uint8Array {
        const packetBytes = embeddingDict.embedding;
        const privateKey   = embeddingDict.privateKey;
        const publicKey    = embeddingDict.publicKey;
        const modeBytes    = utf8(mode);

        const payload = concatBytes([
            u64le(publicKey.length), publicKey,
            u64le(privateKey.length), privateKey,
            u64le(packetBytes.length), packetBytes,
            u64le(modeBytes.length),  modeBytes,
            u64le(identity),
        ]);

        const total = u64le(payload.length);
        return concatBytes([total, payload]);
    }

     /**
     * Unpackages serialized data from a setup node back into its components.
     * @param data Serialized buffer.
     * @returns Tuple [publicKey, packet, mode, identity].
     */
    unpackageData(data: Uint8Array): [Uint8Array, Uint8Array, string, number] {
        let offset = 8; // skip total header

        const pubKeySize = readU64leToNumber(data, offset); offset += 8;
        const publicKey  = sliceBytes(data, offset, pubKeySize); offset += pubKeySize;

        const packetSize = readU64leToNumber(data, offset); offset += 8;
        const packet     = sliceBytes(data, offset, packetSize); offset += packetSize;

        const modeSize   = readU64leToNumber(data, offset); offset += 8;
        const mode       = td.decode(sliceBytes(data, offset, modeSize)); offset += modeSize;

        const identity   = readU64leToNumber(data, offset);

        return [publicKey, packet, mode, identity];
    }

    /**
     * Unpacks encrypted serialized data from an encryptNode into a PacketDict for inspection/cycling.
     * @param data Serialized buffer.
     * @returns Packet dictionary with keys, packet, mode, and identity.
     */
    _unpackEncryptedData(data: Uint8Array): PacketDict {
        let offset = 8;

        const readLength = () => { const n = readU64leToNumber(data, offset); offset += 8; return n; };
        const readBytes  = (len: number) => { const b = sliceBytes(data, offset, len); offset += len; return b; };

        const pubKeySize = readLength();
        const publicKey  = readBytes(pubKeySize);

        const privKeySize = readLength();
        const privateKey  = readBytes(privKeySize);

        const packetSize  = readLength();
        const packet      = readBytes(packetSize);

        const modeSize    = readLength();
        const mode        = td.decode(readBytes(modeSize));

        const identity    = readU64leToNumber(data, offset);

        return { publicKey, privateKey, packet, mode, identity };
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
     * Collects multiple serialized packet arrays into a list of PacketDicts.
     * @param args List of serialized packet arrays.
     * @returns List of packet dictionaries.
     */
    collectPackets(...args: Uint8Array[]): PacketDict[] {
        return args.map(arg => this.unpackageData(arg));
    }

    /**
     * Unpackages serialized array into a PacketDict structure.
     * @param data Serialized array.
     * @returns Packet dictionary.
     */
    unpackageData(data: Uint8Array): PacketDict {
        let offset = 8;

        const readLength = () => { const n = readU64leToNumber(data, offset); offset += 8; return n; };
        const readBytes  = (len: number) => { const b = sliceBytes(data, offset, len); offset += len; return b; };

        const pubKeySize = readLength();
        const publicKey  = readBytes(pubKeySize);

        const privKeySize = readLength();
        const privateKey  = readBytes(privKeySize);

        const packetSize  = readLength();
        const packet      = readBytes(packetSize);

        const modeSize    = readLength();
        const mode        = td.decode(readBytes(modeSize));

        const identity    = readU64leToNumber(data, offset);

        return { publicKey, privateKey, packet, mode, identity };
    }

    /**
     * Recovers and de-obfuscates packet data from a list of PacketDicts.
     * @param packetList List of packet dictionaries.
     * @returns Augmented list with deobfuscated packets.
     */
    recoverPackets(packetList: PacketDict[]): PacketDict[] {
        const out: PacketDict[] = [];

        for (const p of packetList) {
            const privKey = p.privateKey;
            const pubKey  = p.publicKey;

            const combined = concatBytes([privKey, pubKey]);
            const embedded = p.packet;
            const chunkSize = vc.getChunkSize(embedded);
            const deobf = vc.involutePacket(embedded, combined, chunkSize);

            out.push({ ...p, deobfPacket: deobf, privateKey: privKey, publicKey: pubKey });
        }
        return out;
    }

    /**
     * Reconstructs original data streams from multiple packet dictionaries.
     * @param packetList List of packet dictionaries.
     * @returns Reconstructed data as a list of Uint8Arrays.
     * @throws If validation checks fail (modes, public key, identities).
     */
    reconstructData(packetList: PacketDict[]): Uint8Array[] {
        const numParties = packetList.length;
        const firstMode = packetList[0].mode;
        const firstPub  = packetList[0].publicKey;

        for (let i = 1; i < numParties; i++) {
            if (packetList[i].mode !== firstMode) throw new Error('All packets must have the same mode');
            if (!equalBytes(packetList[i].publicKey, firstPub)) throw new Error('All packets must have the same public key');
        }
        for (let i = 0; i < numParties; i++) {
            if (!packetList[i].deobfPacket) throw new Error('Call recoverPackets first');
        }

        const ids = new Set(packetList.map(p => p.identity));
        if (ids.size !== numParties) throw new Error('All packets must have a unique identity');
        for (let i = 0; i < numParties; i++) if (!ids.has(i)) throw new Error('Identities must be 0..N-1');

        const privs = new Array<Uint8Array>(numParties);
        const data  = new Array<Uint8Array>(numParties);
        for (const p of packetList) {
            privs[p.identity] = p.privateKey;
            data[p.identity]  = p.deobfPacket!;
        }
        return vc.invData(firstPub, privs, data);
    }

    /**
     * Decrypts ciphertext using AES-CTR mode.
     * @param ciphertext Encrypted data as Uint8Array.
     * @param nonce Nonce arrays.
     * @param privateKey Private key arrays.
     * @param numIter Number of iterations (default 250,000).
     * @returns Decrypted plaintext as Uint8Array.
     */
    async decryptData(
        ciphertext: Uint8Array,
        nonce: Uint8Array,
        privateKey: Uint8Array,
        numIter = 250_000
    ): Promise<Uint8Array> {
        return utils.decryptAESCTR(privateKey, nonce, ciphertext, numIter);
    }


    /**
     * Decrypts ciphertext using AES-GCM mode (authenticated encryption).
     * @param ciphertext Encrypted data as Uint8Array.
     * @param metadata Metadata array containing nonce + tag.
     * @param privateKey Private key array.
     * @param numIter Number of iterations (default 250,000).
     * @returns Decrypted plaintext as Uint8Array.
     */
    async _decryptData(
        ciphertext: Uint8Array,
        metadata: Uint8Array,
        privateKey: Uint8Array,
        numIter = 250_000
    ): Promise<Uint8Array> {
        const nonce = metadata.subarray(0, 12);
        const tag   = metadata.subarray(12);
        return utils.decryptAESGCM(privateKey, nonce, ciphertext, tag, numIter);
    }

    /**
     * Reassembles a list of data streams into the final data.
     * @param streamList List of data chunks as Uint8Arrays.
     * @param mode Mode string.
     * @returns Recombined data as Uint8Array.
     */
    reassembleData(streamList: Uint8Array[], mode: string): Uint8Array {
        const arrays = streamList.map(s => new Uint8Array(s))
        return utils.recombineData(mode, arrays);
    }

    /**
     * Obfuscates data based on key and conditional values, for deobfuscation, but using involutive approach, so same name.
     * @param packet Data packet as Uint8Array.
     * @param privateKey Private key arraay.
     * @param lowBound Lower bound.
     * @param highBound Upper bound.
     * @param testValue Value to test (float).
     * @returns Tuple of [obfuscated data, chunk size].
     */
    obfuscateData(
        packet: Uint8Array,
        privateKey: Uint8Array,
        lowBound: bigint,
        highBound: bigint,
        testValue: number // TS equivalent of np.float32
        ): [Uint8Array, number] {
        const saltArray = new Uint8Array(privateKey);
        const chunkSize = vc.getChunkSize(packet);
        const invPacket = vc.condInvolutePacket(packet, saltArray, chunkSize, lowBound, highBound, testValue);
        return [new Uint8Array(invPacket), chunkSize];
    }

}

export async function setupNode(
    data: Uint8Array,
    condLow: number,
    condHigh: number,
    encrypt = false
    ): Promise<[Record<string, any>, Record<string, any>]> {
    const setupNode = new SetupNode('Authoriser');

    // 32-byte seed for keygen
    const seed: Uint8Array = utils.randomBytes(32);

    const publicKey: Uint8Array = setupNode.genPublicKey(seed);
    const privateKey: Uint8Array = setupNode.genPrivateKey('obf_privateKey', seed);

    let encrypted: Uint8Array;
    let nonce: Uint8Array;

    if (encrypt) {
        [encrypted, nonce] = await setupNode.encryptData(data, privateKey);
    } else {
        encrypted = data.slice();
        nonce = new Uint8Array(0);
    }

    const testVal = (condLow + condHigh) / 2;

    // implementConditions returns numbers; convert to bigint for condInvolute
    const [lowValNum, highValNum] = setupNode.implementConditions(condLow, condHigh, privateKey);
    const lowVal = BigInt(lowValNum);
    const highVal = BigInt(highValNum);

    const [obfData,_,padding] = setupNode.obfuscateData(encrypted, privateKey, lowVal, highVal, testVal);

    const publicData: Record<string, any> = {
        data: obfData,
        key: publicKey,
    };

    const privateData: Record<string, any> = {
        key: privateKey,
        low_val: lowVal,
        high_val: highVal,
        nonce: nonce,
        padding: padding
    };

    return [publicData, privateData];
}

export function distributeData(
    publicData: Record<string, any>,
    streamMode: string,
    numParties: number
    ): Uint8Array[] {
    const setupNode = new SetupNode('');
    const mode = `${streamMode}${numParties}`;

    const packets: Uint8Array[] = [];
    for (let i = 0; i < numParties; i++) {
        const packet = setupNode.packageData(publicData.data as Uint8Array, publicData.key as Uint8Array, mode, i);
        packets.push(packet);
    }
    return packets;
}

export function encryptNode(
    packet: Uint8Array,
    nodeLabel = 'encryption_node'
    ): Uint8Array {
    const enc = new EncryptNode(nodeLabel);
    const [publicKey, packetData, mode, identity] = enc.unpackageData(packet);

    const privateKey = enc.genPrivateKey('label_privateKey', utils.randomBytes(32));
    const embedding = enc.encryptData(packetData, privateKey, publicKey, mode, identity);

    return enc.packageData(embedding, mode, identity);
}

export function cycleKey(
    encryptedPacket: Uint8Array,
    nodeLabel = 'encryption_node'
    ): Uint8Array {
    const enc = new EncryptNode(nodeLabel);

    const data = enc._unpackEncryptedData(encryptedPacket);
    const newPrivateKey = enc.genPrivateKey('cycled_key', utils.randomBytes(32));

    const cycled = enc.cycleKey(
        data.packet,
        data.privateKey,
        newPrivateKey,
        data.publicKey
    );

    const embeddingDict: EmbeddingDict = {
        embedding: cycled,
        privateKey: newPrivateKey,
        publicKey: data.publicKey,
        identity: data.identity,
    };

    return enc.packageData(embeddingDict, data.mode, data.identity);
}

export async function decryptNode(
    privateData: Record<string, any>,
    testValue: number,
    encrypt: boolean,
    ...args: Uint8Array[]
    ): Promise<Uint8Array> {
    const dec = new DecryptNode('Veriphier');

    const packetList = dec.collectPackets(...args);
    const recovered = dec.recoverPackets(packetList);
    const streams = dec.reconstructData(recovered);
    const reconstructed = dec.reassembleData(streams, packetList[0].mode);

    let [deobf,_] = dec.obfuscateData(
        reconstructed,
        privateData.key as Uint8Array,
        privateData.low_val as bigint,
        privateData.high_val as bigint,
        testValue
    );
    deobf = privateData.padding > 0
        ? deobf.subarray(0, deobf.length - privateData.padding)
        : deobf;
    if (encrypt) {
        // if your utils.decryptAESCTR is async in the browser build, await it here
        const plaintext = await dec.decryptData(
        deobf,
        privateData.nonce as Uint8Array,
        privateData.key as Uint8Array
        );
        return plaintext;
    }

    return deobf;
}
