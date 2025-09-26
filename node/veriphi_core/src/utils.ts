import { randomBytes, pbkdf2Sync, createCipheriv, createDecipheriv } from 'crypto';
import assert from 'node:assert/strict';


export function deriveEncryptionKey(
    privateKey: Buffer,
    count: number = 250_000,
    context: Buffer = Buffer.from('setup_encryption')
): Buffer {
    return pbkdf2Sync(privateKey, context, count, 32, 'sha256');
}

export function encryptAESGCM(
    privateKey: Buffer,
    plaintext: Buffer,
    numIter: number = 250_000
): [cipherText: Buffer, tag: Buffer, nonce: Buffer ] {
    const key = deriveEncryptionKey(privateKey, numIter);
    const nonce = randomBytes(12)
    const aesCipher = createCipheriv('aes-256-gcm', key, nonce);

    const cipherText = Buffer.concat([aesCipher.update(plaintext), aesCipher.final()]);
    const tag = aesCipher.getAuthTag();
    return [ cipherText, tag, nonce ];
}

export function decryptAESGCM(
  privateKey: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
  numIter = 250_000
): Buffer {
  const key = deriveEncryptionKey(privateKey, numIter);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('Decryption failed - data may be corrupted or key is wrong');
  }
}

export function encryptAESCTR(
  privateKey: Buffer,
  plaintext: Buffer,
  numIter: number = 250_000
): [ciphertext: Buffer, nonce: Buffer ] {
  const key = deriveEncryptionKey(privateKey, numIter);
  const nonce = randomBytes(16); // 64-bit nonce
  const cipher = createCipheriv('aes-256-ctr', key, nonce);

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return [ciphertext, nonce ];
}

export function decryptAESCTR(
  privateKey: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  numIter = 250_000
): Buffer {
  const key = deriveEncryptionKey(privateKey, numIter);
  const decipher = createDecipheriv('aes-256-ctr', key, nonce);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}


/////////////////////////////////////////
// Helper functions for data packaging //
/////////////////////////////////////////

export function streamData(mode: string, data: Buffer): Buffer[] {
  assert(mode.length === 2, 'Mode must consist of a letter and a number');
  const letter = mode[0].toUpperCase();
  const numStreams = parseInt(mode[1]);
  const remainder = (numStreams - (data.length % numStreams)) % numStreams;
  const paddedData = remainder > 0 ? Buffer.concat([data, Buffer.alloc(remainder)]) : data;

  switch (letter) {
    case 'E':
      return sEqData(numStreams, paddedData);
    case 'K':
      return sKipData(numStreams, paddedData);
    default:
      throw new Error(`Unknown mode: ${letter}`);
  }
}

/**
 * Equal partitioning of buffer into N parts.
 */
function sEqData(numStreams: number, data: Buffer): Buffer[] {
  const streamLength = data.length / numStreams;
  const streams: Buffer[] = [];

  for (let i = 0; i < numStreams; i++) {
    streams.push(data.slice(i * streamLength, (i + 1) * streamLength));
  }

  return streams;
}

/**
 * Interleaved splitting of buffer across N parts.
 */
function sKipData(numStreams: number, data: Buffer): Buffer[] {
  const streamLength = data.length / numStreams;
  const streams: Buffer[] = Array.from({ length: numStreams }, () => Buffer.alloc(streamLength));

  for (let i = 0; i < numStreams; i++) {
    for (let j = 0; j < streamLength; j++) {
      streams[i][j] = data[i + j * numStreams];
    }
  }

  return streams;
}

/**
 * Recombine multiple Buffer streams using the given mode.
 */
export function recombineData(mode: string, data: Buffer[]): Buffer {
    assert(mode.length === 2, 'Mode must consist of a letter and a number');
    const modeLetter = mode[0].toUpperCase();
    const numStreams = parseInt(mode[1]);

    assert.strictEqual(numStreams, data.length, `Expected ${numStreams} streams, got ${data.length}`);
    const streamLength = data[0].length;
    assert(data.every(buf => buf.length === streamLength), 'All streams must have the same length');

    const stacked = Buffer.concat(data);

    switch (modeLetter) {
        case 'E':
        return recombineSequential(numStreams, stacked);
        case 'K':
        return recombineInterleaved(numStreams, stacked);
        default:
        throw new Error(`Unknown mode: ${modeLetter}. Use 'E' for sequential or 'K' for skipping.`);
    }
}

/**
 * Recombine data by simple concatenation (row-wise).
 */
export function recombineSequential(numStreams: number, data: Buffer): Buffer {
  assert(data.length % numStreams === 0, 'Data length must be divisible by number of streams');
  return Buffer.from(data); // clone
}

/**
 * Recombine interleaved data (column-wise).
 */
export function recombineInterleaved(numStreams: number, data: Buffer): Buffer {
  assert(data.length % numStreams === 0, 'Data length must be divisible by number of streams');
  const streamLength = data.length / numStreams;
  const recombined = Buffer.alloc(data.length);

  for (let i = 0; i < streamLength; i++) {
    for (let j = 0; j < numStreams; j++) {
      recombined[i * numStreams + j] = data[j * streamLength + i];
    }
  }

  return recombined;
}

/**
 * Calculate how many bytes must be appended so that (currentLen + n)
 * is BOTH even and divisible by 3 — i.e., divisible by 6.
 *
 * Math trick: find the smallest n ≥ 0 with (currentLen + n) % 6 === 0
 * => n = (6 - (currentLen % 6)) % 6
 */
export function calculatePaddingLength(currentLen: number): number {
  if (currentLen < 0 || !Number.isInteger(currentLen)) {
    throw new TypeError("currentLen must be a non-negative integer");
  }
  return (6 - (currentLen % 6)) % 6;
}

/**
 * Generate cryptographically secure random padding bytes.
 * Returns an empty Uint8Array when paddingLen == 0.
 */
export function generatePaddingBytes(paddingLen: number): Uint8Array {
  if (paddingLen < 0 || !Number.isInteger(paddingLen)) {
    throw new TypeError("paddingLen must be a non-negative integer");
  }
  if (paddingLen === 0) return new Uint8Array(0);
  // Buffer is a Uint8Array subclass; OK to return directly.
  return randomBytes(paddingLen);
}

/**
 * Convenience helper: given a packet, compute and append padding bytes
 * so the final length is divisible by 6. Returns both padding and padded packet.
 */
export function padPacket(
  packet: Uint8Array
): { padded: Uint8Array; padding: Uint8Array } {
  const padLen = calculatePaddingLength(packet.length);
  const padding = generatePaddingBytes(padLen);
  if (padLen === 0) {
    return { padded: packet, padding };
  }
  const padded = new Uint8Array(packet.length + padLen);
  padded.set(packet, 0);
  padded.set(padding, packet.length);
  return { padded, padding };
}