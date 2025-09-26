
function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

export function assert(cond: any, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

//////////////////////////////
// Web Crypto compatibility //
//////////////////////////////

const cryptoAPI: Crypto | undefined = (globalThis as any).crypto;
assert(cryptoAPI && cryptoAPI.subtle, "Web Crypto not available (need HTTPS + modern browser).");

// random bytes
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  cryptoAPI!.getRandomValues(out);
  return out;
}

function asArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.slice(u8.byteOffset, u8.byteOffset + u8.byteLength).buffer;
}

// PBKDF2-SHA256 -> key bytes
async function pbkdf2SHA256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations = 250_000,
  lengthBytes = 32
): Promise<Uint8Array> {
  const pwKey = await cryptoAPI!.subtle.importKey("raw", asArrayBuffer(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await cryptoAPI!.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt:asArrayBuffer(salt), iterations },
    pwKey,
    lengthBytes * 8
  );
  return new Uint8Array(bits as ArrayBuffer);
}

export async function deriveEncryptionKey(
  privateKey: Uint8Array,
  count: number = 250_000,
  context: Uint8Array = new TextEncoder().encode("setup_encryption")
): Promise<Uint8Array> {
  return pbkdf2SHA256(privateKey, context, count, 32);
}

export async function encryptAESGCM(
  privateKey: Uint8Array,
  plaintext: Uint8Array,
  numIter: number = 250_000
): Promise<[cipherText: Uint8Array, tag: Uint8Array, nonce: Uint8Array]> {
  const keyBytes = await deriveEncryptionKey(privateKey, numIter);
  const key = await cryptoAPI!.subtle.importKey("raw", asArrayBuffer(keyBytes), { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = randomBytes(12); // 96-bit IV

  const ctWithTag = new Uint8Array(
    await cryptoAPI!.subtle.encrypt({ name: "AES-GCM", iv: asArrayBuffer(nonce) }, key, asArrayBuffer(plaintext))
  );

  // Split tag (last 16 bytes by default)
  const tagLen = 16;
  const tag = ctWithTag.slice(ctWithTag.length - tagLen);
  const cipherText = ctWithTag.slice(0, ctWithTag.length - tagLen);
  return [cipherText, tag, nonce];
}

export async function decryptAESGCM(
  privateKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  numIter = 250_000
): Promise<Uint8Array> {
  const keyBytes = await deriveEncryptionKey(privateKey, numIter);
  const key = await cryptoAPI!.subtle.importKey("raw", asArrayBuffer(keyBytes), { name: "AES-GCM" }, false, ["decrypt"]);

  // Re-join ct || tag to feed into SubtleCrypto
  const ctWithTag = concatBytes([ciphertext, tag]);
  try {
    const pt = await cryptoAPI!.subtle.decrypt({ name: "AES-GCM", iv: asArrayBuffer(nonce) }, key, asArrayBuffer(ctWithTag));
    return new Uint8Array(pt);
  } catch {
    throw new Error("Decryption failed - data may be corrupted or key is wrong");
  }
}

export async function encryptAESCTR(
  privateKey: Uint8Array,
  plaintext: Uint8Array,
  numIter: number = 250_000
): Promise<[ciphertext: Uint8Array, nonce: Uint8Array]> {
  const keyBytes = await deriveEncryptionKey(privateKey, numIter);
  const key = await cryptoAPI!.subtle.importKey("raw", asArrayBuffer(keyBytes), { name: "AES-CTR" }, false, ["encrypt"]);
  const nonce = randomBytes(16); // 128-bit counter block

  // Use 64-bit counter length for broad compat
  const ct = await cryptoAPI!.subtle.encrypt(
    { name: "AES-CTR", counter: asArrayBuffer(nonce), length: 64 },
    key,
    asArrayBuffer(plaintext)
  );
  return [new Uint8Array(ct), nonce];
}

export async function decryptAESCTR(
  privateKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  numIter = 250_000
): Promise<Uint8Array> {
  const keyBytes = await deriveEncryptionKey(privateKey, numIter);
  const key = await cryptoAPI!.subtle.importKey("raw", asArrayBuffer(keyBytes), { name: "AES-CTR" }, false, ["decrypt"]);
  const pt = await cryptoAPI!.subtle.decrypt(
    { name: "AES-CTR", counter: asArrayBuffer(nonce), length: 64 },
    key,
    asArrayBuffer(ciphertext)
  );
  return new Uint8Array(pt);
}

/////////////////////////////////////////
// Helper functions for data packaging //
/////////////////////////////////////////

export function streamData(mode: string, data: Uint8Array): Uint8Array[] {
  assert(mode.length === 2, "Mode must consist of a letter and a number");
  const letter = mode[0].toUpperCase();
  const numStreams = parseInt(mode[1], 10);
  const remainder = (numStreams - (data.length % numStreams)) % numStreams;
  const paddedData = remainder > 0 ? concatBytes([data, new Uint8Array(remainder)]) : data;

  switch (letter) {
    case "E": return sEqData(numStreams, paddedData);
    case "K": return sKipData(numStreams, paddedData);
    default: throw new Error(`Unknown mode: ${letter}`);
  }
}

function sEqData(numStreams: number, data: Uint8Array): Uint8Array[] {
  const streamLength = data.length / numStreams;
  const streams: Uint8Array[] = [];
  for (let i = 0; i < numStreams; i++) {
    streams.push(data.slice(i * streamLength, (i + 1) * streamLength));
  }
  return streams;
}

function sKipData(numStreams: number, data: Uint8Array): Uint8Array[] {
  const streamLength = data.length / numStreams;
  const streams: Uint8Array[] = Array.from({ length: numStreams }, () => new Uint8Array(streamLength));
  for (let i = 0; i < numStreams; i++) {
    for (let j = 0; j < streamLength; j++) {
      streams[i][j] = data[i + j * numStreams];
    }
  }
  return streams;
}

export function recombineData(mode: string, data: Uint8Array[]): Uint8Array {
  assert(mode.length === 2, "Mode must consist of a letter and a number");
  const modeLetter = mode[0].toUpperCase();
  const numStreams = parseInt(mode[1], 10);

  assert(numStreams === data.length, `Expected ${numStreams} streams, got ${data.length}`);
  const streamLength = data[0].length;
  assert(data.every((buf) => buf.length === streamLength), "All streams must have the same length");

  const stacked = concatBytes(data);

  switch (modeLetter) {
    case "E": return recombineSequential(numStreams, stacked);
    case "K": return recombineInterleaved(numStreams, stacked);
    default: throw new Error(`Unknown mode: ${modeLetter}. Use 'E' for sequential or 'K' for skipping.`);
  }
}

export function recombineSequential(numStreams: number, data: Uint8Array): Uint8Array {
  assert(data.length % numStreams === 0, "Data length must be divisible by number of streams");
  return data.slice();
}

export function recombineInterleaved(numStreams: number, data: Uint8Array): Uint8Array {
  assert(data.length % numStreams === 0, "Data length must be divisible by number of streams");
  const streamLength = data.length / numStreams;
  const out = new Uint8Array(data.length);
  for (let i = 0; i < streamLength; i++) {
    for (let j = 0; j < numStreams; j++) {
      out[i * numStreams + j] = data[j * streamLength + i];
    }
  }
  return out;
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