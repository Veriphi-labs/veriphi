import { describe, it, expect } from 'vitest';

import * as ic from '../src/index.js';
import { randomBytes, decryptAESCTR, decryptAESGCM, encryptAESCTR, encryptAESGCM } from '../src/utils.js';

function fillRandom(u8: Uint8Array) {
  if (typeof globalThis.crypto?.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(u8);
    return u8;
  }
  const r = randomBytes(u8.length);
  u8.set(r);
  return u8;
}

function randFill(len: number): Uint8Array {
  return randomBytes(len);
}

const te = new TextEncoder();

describe('AES GCM Encryption Tests (Uint8Array)', () =>  {
  it('aesGCMBasic', async () => {
    const privateKey = randomBytes(32); // 32 bytes for AES-256
    const plainText = te.encode('testing AES implementation in Typescript');

    const [cipherText, tag, nonce] = await encryptAESGCM(privateKey, plainText);
    const recoveredText = await decryptAESGCM(privateKey, nonce, cipherText, tag);

    // ciphertext should differ from plaintext
    expect(cipherText).not.toEqual(plainText);

    // recovered should equal plaintext
    expect(recoveredText).toEqual(plainText);
  });

  it('aesGcmDetectsCiphertextTampering', async () => {
    const privateKey = randomBytes(32);
    const plaintext = te.encode('testing AES implementation in Typescript');
    const [ciphertext, tag, nonce] = await encryptAESGCM(privateKey, plaintext);

    // Modify one bit of ciphertext
    const modifiedCiphertext = new Uint8Array(ciphertext);
    modifiedCiphertext[0] ^= 1;

    await expect(
      decryptAESGCM(privateKey, nonce, modifiedCiphertext, tag)
    ).rejects.toThrow();
  });

  it('aesGcmDetectsTagTampering', async () => {
    const privateKey = randomBytes(32);
    const plaintext = te.encode('testing AES implementation in Typescript');
    const [ciphertext, tag, nonce] = await encryptAESGCM(privateKey, plaintext);

    // Modify one bit of tag
    const modifiedTag = new Uint8Array(tag);
    modifiedTag[0] ^= 1;

    await expect(
      decryptAESGCM(privateKey, nonce, ciphertext, modifiedTag)
    ).rejects.toThrow();
  });

  it('aesGcmDetectsWrongNonce', async () => {
    const privateKey = randomBytes(32);
    const plaintext = te.encode('testing AES implementation in Typescript');
    const [ciphertext, tag] = await encryptAESGCM(privateKey, plaintext);

    // Use wrong nonce (12 bytes for GCM)
    const wrongNonce = randomBytes(12);

    await expect(
      decryptAESGCM(privateKey, wrongNonce, ciphertext, tag)
    ).rejects.toThrow();
  });
});

describe('AES CTR Encryption Tests (Uint8Array)', () => {
  it('aesCtrBasic', async () => {
    const privateKey = randomBytes(32); // 32 bytes for AES-256
    const plaintext = te.encode('testing AES implementation in Typescript');

    const [ciphertext, nonce] = await encryptAESCTR(privateKey, plaintext);
    const recoveredText = await decryptAESCTR(privateKey, nonce, ciphertext);

    expect(ciphertext).not.toEqual(plaintext);
    expect(recoveredText).toEqual(plaintext);
  });

  it('aesCtrNoTamperingDetection', async () => {
    // CTR mode does NOT detect tampering - decryption succeeds but produces garbage
    const privateKey = randomBytes(32);
    const plaintext = te.encode('testing AES implementation in Typescript');
    const [ciphertext, nonce] = await encryptAESCTR(privateKey, plaintext);

    // Modify one bit of ciphertext
    const modifiedCiphertext = new Uint8Array(ciphertext);
    modifiedCiphertext[0] ^= 1;

    // CTR decryption succeeds but produces corrupted data
    const corruptedPlaintext = await decryptAESCTR(privateKey, nonce, modifiedCiphertext);

    // The decryption succeeds (no exception)
    expect(corruptedPlaintext).not.toEqual(plaintext);
    expect(corruptedPlaintext.length).toBe(plaintext.length); // Same length though
  });

  it('aesCtrWrongNonceProducesGarbage', async () => {
    // CTR with wrong nonce produces garbage output, no authentication failure
    const privateKey = randomBytes(32);
    const plaintext = te.encode('testing AES implementation in Typescript');
    const [ciphertext] = await encryptAESCTR(privateKey, plaintext);

    // Use wrong nonce (CTR uses 16-byte nonce)
    const wrongNonce = randomBytes(16);
    const garbageOutput = await decryptAESCTR(privateKey, wrongNonce, ciphertext);

    expect(garbageOutput).not.toEqual(plaintext);
    expect(garbageOutput.length).toBe(plaintext.length);
  });

  it('aesCtrBitFlippingAttack', async () => {
    // Demonstrates CTR's vulnerability to bit-flipping attacks
    const privateKey = randomBytes(32);
    const plaintext = te.encode('ATTACK AT DAWN');
    const [ciphertext, nonce] = await encryptAESCTR(privateKey, plaintext);

    // Test for cipher modification
    const targetChange = te.encode('ATTACK');
    const desiredText = te.encode('DEFEND');
    const xorDiff = new Uint8Array(targetChange.length);
    for (let i = 0; i < xorDiff.length; i++) {
      xorDiff[i] = targetChange[i] ^ desiredText[i];
    }

    const modifiedCiphertext = new Uint8Array(ciphertext);
    for (let i = 0; i < xorDiff.length; i++) {
      modifiedCiphertext[i] ^= xorDiff[i];
    }

    const modifiedPlaintext = await decryptAESCTR(privateKey, nonce, modifiedCiphertext);

    expect(modifiedPlaintext.slice(0, 6)).toEqual(te.encode('DEFEND'));
    expect(modifiedPlaintext).not.toEqual(plaintext);
  });
});


describe('Setup Node Tests', () => {
  it('involuteConditionTrue', () => {
    const testData = fillRandom(new Uint8Array(1000));

    const nodeA = new ic.SetupNode('A');
    const masterSeed = randomBytes(32);
    const privateKey = nodeA.genPrivateKey('masterPrivateKey', masterSeed);

    const [lowValue, highValue] = nodeA.implementConditions(-1.0, 1.0, privateKey);
    const [obfuscatedPacket] = nodeA.obfuscateData(
      testData,
      privateKey,
      BigInt(lowValue),
      BigInt(highValue),
      0.0
    );

    expect(obfuscatedPacket).not.toEqual(testData);
  });

  it('involuteFailedCondition', () => {
    const testData = fillRandom(new Uint8Array(100));

    const nodeA = new ic.SetupNode('A');
    const masterSeed = randomBytes(32);
    const privateKey = nodeA.genPrivateKey('masterPrivateKey', masterSeed);

    const [lowValue, highValue] = nodeA.implementConditions(-1.0, 1.0, privateKey);
    const [obfuscatedPacket] = nodeA.obfuscateData(
      testData,
      privateKey,
      BigInt(lowValue),
      BigInt(highValue),
      0.0
    );

    // Obfuscated packet should not resemble original, but should have the same values
    expect(obfuscatedPacket).not.toEqual(testData);

    const sortedObf = Array.from(obfuscatedPacket).sort((a, b) => a - b);
    const sortedOriginal = Array.from(testData).sort((a, b) => a - b);
    expect(sortedObf).toEqual(sortedOriginal);

    // Recovered packet should be exactly the same as the original
    const [recoveredPacket] = nodeA.obfuscateData(
      obfuscatedPacket,
      privateKey,
      BigInt(lowValue),
      BigInt(highValue),
      0.5
    );
    expect(recoveredPacket).toEqual(testData);

    // Attempt to recover the original with a failed condition should lead to a different array
    const [recoveredPacketFalse] = nodeA.obfuscateData(
      obfuscatedPacket,
      privateKey,
      BigInt(lowValue),
      BigInt(highValue),
      10.0
    );
    expect(recoveredPacketFalse).not.toEqual(testData);
  });
});

describe('Full Process Tests', () => {
  it('twoWayDecryptionEStyle', async () => {
    const testData = randFill(300);

    // Setup the network
    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB] = ic.distributeData(publicData, 'E', 2);

    // Encrypt the portions
    const authPacket = ic.encryptNode(packetA, 'authoriser');
    const agentPacket = ic.encryptNode(packetB, 'agent');

    // Decrypt the data
    const decryptedData = await ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket);
    expect(decryptedData).toEqual(testData);
  });

  it('twoWayDecryptionKStyle', async () => {
    const testData = randFill(300);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB] = ic.distributeData(publicData, 'K', 2);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    const agentPacket = ic.encryptNode(packetB, 'agent');

    const decryptedData = await ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket);
    expect(decryptedData).toEqual(testData);
  });

  it('threeWayDecryptionEStyle', async () => {
    const testData = randFill(300);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB, packetC] = ic.distributeData(publicData, 'E', 3);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    const agentPacket = ic.encryptNode(packetB, 'agent');
    const targetPacket = ic.encryptNode(packetC, 'target');

    const decryptedData = await ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket);
    expect(decryptedData).toEqual(testData);
  });

  it('threeWayDecryptionKStyle', async () => {
    const testData = randFill(300);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB, packetC] = ic.distributeData(publicData, 'K', 3);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    const agentPacket = ic.encryptNode(packetB, 'agent');
    const targetPacket = ic.encryptNode(packetC, 'target');

    const decryptedData = await ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket);
    expect(decryptedData).toEqual(testData);
  });

  it('publicKeyDecryptionFailure', async () => {
    const testData = randFill(300);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB, packetC] = ic.distributeData(publicData, 'K', 3);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    let agentPacket = ic.encryptNode(packetB, 'agent');
    const targetPacket = ic.encryptNode(packetC, 'target');

    // Modify one of the public keys
    const decryptNode = new ic.DecryptNode('');
    const agentData = decryptNode.unpackageData(agentPacket);
    const agentPublicKey = new Uint8Array(agentData.publicKey);
    const modAgentPublicKey = new Uint8Array(agentPublicKey);
    // swap first two bytes
    [modAgentPublicKey[0], modAgentPublicKey[1]] = [modAgentPublicKey[1], modAgentPublicKey[0]];

    const encryptNode = new ic.EncryptNode('');
    const modifiedAgentPacket: ic.EmbeddingDict = {
      embedding: new Uint8Array(agentData.packet),
      privateKey: new Uint8Array(agentData.privateKey),
      publicKey: modAgentPublicKey,
      identity: agentData.identity
    };

    agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity);

    // Decrypt the data (expect failure OR wrong result)
    try {
      const decryptedData = await ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket);
      expect(decryptedData).not.toEqual(testData);
    } catch {
      // acceptable failure path
    }
  });

  it('publicKeyDecryptionCatastrophicFailure2', async () => {
    const testData = randFill(600);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB] = ic.distributeData(publicData, 'K', 2);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    let agentPacket = ic.encryptNode(packetB, 'agent');

    // Replace agent public key with a fresh random one
    const decryptNode = new ic.DecryptNode('');
    const agentData = decryptNode.unpackageData(agentPacket);
    const setupNode = new ic.SetupNode('__');
    const encryptNode = new ic.EncryptNode('');

    const modifiedAgentPacket: ic.EmbeddingDict = {
      embedding: new Uint8Array(agentData.packet),
      privateKey: new Uint8Array(agentData.privateKey),
      publicKey: new Uint8Array(setupNode.genPublicKey(randomBytes(32))),
      identity: agentData.identity
    };

    agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity);

    await expect(ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket)).rejects.toBeTruthy();
  });

  it('publicKeyDecryptionCatastrophicFailure3', async () => {
    const testData = randFill(600);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB, packetC] = ic.distributeData(publicData, 'E', 3);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    let agentPacket = ic.encryptNode(packetB, 'agent');
    const targetPacket = ic.encryptNode(packetC, 'Domain');

    // Replace agent public key with a fresh random one
    const decryptNode = new ic.DecryptNode('');
    const agentData = decryptNode.unpackageData(agentPacket);
    const setupNode = new ic.SetupNode('__');
    const encryptNode = new ic.EncryptNode('');

    const modifiedAgentPacket: ic.EmbeddingDict = {
      embedding: new Uint8Array(agentData.packet),
      privateKey: new Uint8Array(agentData.privateKey),
      publicKey: new Uint8Array(setupNode.genPublicKey(randomBytes(32))),
      identity: agentData.identity
    };

    agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity);

    await expect(ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket)).rejects.toBeTruthy();
  });

  it('keyCycling', async () => {
    const testData = randFill(300);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB, packetC] = ic.distributeData(publicData, 'E', 3);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    const agentPacket = ic.encryptNode(packetB, 'agent');
    const targetPacket = ic.encryptNode(packetC, 'target');

    const cycledAgentPacket = ic.cycleKey(agentPacket, 'agent');

    const decryptedData = await ic.decryptNode(privateData, 1.0, false, authPacket, cycledAgentPacket, targetPacket);
    expect(decryptedData).toEqual(testData);
  });

  it('privateKeyDecryptionFailure3', async () => {
    const testData = randFill(300);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB, packetC] = ic.distributeData(publicData, 'K', 3);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    let agentPacket = ic.encryptNode(packetB, 'agent');
    const targetPacket = ic.encryptNode(packetC, 'target');

    // Swap two bytes in agent's private key
    const decryptNode = new ic.DecryptNode('');
    const agentData = decryptNode.unpackageData(agentPacket);
    const modAgentPrivateKey = new Uint8Array(agentData.privateKey);
    [modAgentPrivateKey[0], modAgentPrivateKey[1]] = [modAgentPrivateKey[1], modAgentPrivateKey[0]];

    const encryptNode = new ic.EncryptNode('');
    const modifiedAgentPacket: ic.EmbeddingDict = {
      embedding: new Uint8Array(agentData.packet),
      privateKey: modAgentPrivateKey,
      publicKey: new Uint8Array(agentData.publicKey),
      identity: agentData.identity
    };

    agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity);

    const decryptedData = await ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket);
    expect(decryptedData).not.toEqual(testData);
  });

  it('privateKeyDecryptionFailure2', async () => {
    const testData = randFill(300);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB] = ic.distributeData(publicData, 'E', 2);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    let agentPacket = ic.encryptNode(packetB, 'agent');

    // Swap two bytes in agent's private key
    const decryptNode = new ic.DecryptNode('');
    const agentData = decryptNode.unpackageData(agentPacket);
    const modAgentPrivateKey = new Uint8Array(agentData.privateKey);
    [modAgentPrivateKey[0], modAgentPrivateKey[1]] = [modAgentPrivateKey[1], modAgentPrivateKey[0]];

    const encryptNode = new ic.EncryptNode('');
    const modifiedAgentPacket: ic.EmbeddingDict = {
      embedding: new Uint8Array(agentData.packet),
      privateKey: modAgentPrivateKey,
      publicKey: new Uint8Array(agentData.publicKey),
      identity: agentData.identity
    };

    agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity);

    const decryptedData = await ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket);
    expect(decryptedData).not.toEqual(testData);
  });

  it('conditionFailure3', async () => {
    const testData = randFill(300);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB, packetC] = ic.distributeData(publicData, 'E', 3);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    const agentPacket = ic.encryptNode(packetB, 'agent');
    const targetPacket = ic.encryptNode(packetC, 'target');

    const decryptedData = await ic.decryptNode(privateData, -1.0, false, authPacket, agentPacket, targetPacket);
    expect(decryptedData).not.toEqual(testData);
  });

  it('conditionFailure2', async () => {
    const testData = randFill(300);

    const [publicData, privateData] = await ic.setupNode(testData, 0.0, 10.0);
    const [packetA, packetB] = ic.distributeData(publicData, 'E', 2);

    const authPacket = ic.encryptNode(packetA, 'authoriser');
    const agentPacket = ic.encryptNode(packetB, 'agent');

    const decryptedData = await ic.decryptNode(privateData, 11.0, false, authPacket, agentPacket);
    expect(decryptedData).not.toEqual(testData);
  });
});