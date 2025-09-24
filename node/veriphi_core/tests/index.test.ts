import * as crypto from 'crypto'
import assert from 'node:assert/strict';
import { describe, test } from 'node:test'

import * as ic from '../src/index.js';
import { decryptAESCTR, decryptAESGCM, encryptAESCTR, encryptAESGCM } from '../src/utils.js';

describe('AES GCM Encryption Tests', () => {
    test('aesGCMBasic', () => {
        const privateKey = crypto.randomBytes(256)
        const plainText = Buffer.from('testing AES implementation in Typescript')
        const [cipherText, tag, nonce] = encryptAESGCM(privateKey, plainText)
        const recoveredText = decryptAESGCM(privateKey, nonce, cipherText, tag)
        assert.notDeepEqual(cipherText, plainText)
        assert.deepEqual(recoveredText, plainText)
    })

    test('aesGcmDetectsCiphertextTampering', () => {
        const privateKey = crypto.randomBytes(256)
        const plaintext = Buffer.from('testing AES implementation in Typescript')
        const [ciphertext, tag, nonce] = encryptAESGCM(privateKey, plaintext)

        // Modify one bit of ciphertext
        const modifiedCiphertext = Buffer.from(ciphertext)
        modifiedCiphertext[0] ^= 1

        assert.throws(() => {
            decryptAESGCM(privateKey, nonce, modifiedCiphertext, tag)
        })
    })

    test('aesGcmDetectsTagTampering', () => {
        const privateKey = crypto.randomBytes(256)
        const plaintext = Buffer.from('testing AES implementation in Typescript')
        const [ciphertext, tag, nonce] = encryptAESGCM(privateKey, plaintext)

        // Modify one bit of tag
        const modifiedTag = Buffer.from(tag)
        modifiedTag[0] ^= 1

        assert.throws(() => {
            decryptAESGCM(privateKey, nonce, ciphertext, modifiedTag)
        })
    })

    test('aesGcmDetectsWrongNonce', () => {
        const privateKey = crypto.randomBytes(256)
        const plaintext = Buffer.from('testing AES implementation in Typescript')
        const [ciphertext, tag, nonce] = encryptAESGCM(privateKey, plaintext)

        // Use wrong nonce
        const wrongNonce = crypto.randomBytes(12)

        assert.throws(() => {
            decryptAESGCM(privateKey, wrongNonce, ciphertext, tag)
        })
    })
})

describe('AES CTR Encryption Tests', () => {
    test('aesCtrBasic', () => {
        const privateKey = crypto.randomBytes(256)
        const plaintext = Buffer.from('testing AES implementation in Typescript')
        const [ciphertext, nonce] = encryptAESCTR(privateKey, plaintext)
        const recoveredText = decryptAESCTR(privateKey, nonce, ciphertext)

        assert.notDeepEqual(ciphertext, plaintext)
        assert.deepEqual(recoveredText, plaintext)
    })

    test('aesCtrNoTamperingDetection', () => {
        // CTR mode does NOT detect tampering - decryption succeeds but produces garbage
        const privateKey = crypto.randomBytes(256)
        const plaintext = Buffer.from('testing AES implementation in Typescript')
        const [ciphertext, nonce] = encryptAESCTR(privateKey, plaintext)

        // Modify one bit of ciphertext
        const modifiedCiphertext = Buffer.from(ciphertext)
        modifiedCiphertext[0] ^= 1

        // CTR decryption succeeds but produces corrupted data
        const corruptedPlaintext = decryptAESCTR(privateKey, nonce, modifiedCiphertext)

        // The decryption succeeds (no exception)
        assert.notEqual(corruptedPlaintext, plaintext)
        assert.ok(corruptedPlaintext.length === plaintext.length) // Same length though
    })

    test('aesCtrWrongNonceProducesGarbage', () => {
        // CTR with wrong nonce produces garbage output, no authentication failure
        const privateKey = crypto.randomBytes(256)
        const plaintext = Buffer.from('testing AES implementation in Typescript')
        const [ciphertext, _] = encryptAESCTR(privateKey, plaintext)

        // Use wrong nonce
        const wrongNonce = crypto.randomBytes(16) // CTR uses 16-byte nonce
        const garbageOutput = decryptAESCTR(privateKey, wrongNonce, ciphertext)

        assert.notEqual(garbageOutput, plaintext)
        assert.ok(garbageOutput.length === plaintext.length)
    })

    test('aesCtrBitFlippingAttack', () => {
        // Demonstrates CTR's vulnerability to bit-flipping attacks
        const privateKey = crypto.randomBytes(256)
        const plaintext = Buffer.from('ATTACK AT DAWN')
        const [ciphertext, nonce] = encryptAESCTR(privateKey, plaintext)

        // Test for cipher modification
        const targetChange = Buffer.from('ATTACK')
        const desiredText = Buffer.from('DEFEND')
        const xorDiff = Buffer.alloc(targetChange.length)
        for (let i = 0; i < targetChange.length; i++) {
            xorDiff[i] = targetChange[i] ^ desiredText[i]
        }

        const modifiedCiphertext = Buffer.from(ciphertext)
        for (let i = 0; i < xorDiff.length; i++) {
            modifiedCiphertext[i] ^= xorDiff[i]
        }

        const modifiedPlaintext = decryptAESCTR(privateKey, nonce, modifiedCiphertext)

        assert.deepEqual(modifiedPlaintext.subarray(0, 6), Buffer.from('DEFEND'))
        assert.notDeepEqual(modifiedPlaintext, plaintext)
    })
})

describe('Setup Node Tests', () => {
    test('involuteConditionTrue', () => {
        const testData = new Uint8Array(1000)
        crypto.randomFillSync(testData)

        const nodeA = new ic.SetupNode('A')
        const masterSeed = crypto.randomBytes(32)
        const privateKey = nodeA.genPrivateKey('masterPrivateKey', Buffer.from(masterSeed))
        const [lowValue, highValue] = nodeA.implementConditions(-1.0, 1.0, privateKey)
        const [obfuscatedPacket] = nodeA.obfuscateData(Buffer.from(testData), privateKey, lowValue, highValue, 0.0)

        assert.notEqual(obfuscatedPacket, testData)
    })

    test('involuteFailedCondition', () => {
        const testData = new Uint8Array(100)
        crypto.randomFillSync(testData)

        const nodeA = new ic.SetupNode('A')
        const masterSeed = crypto.randomBytes(32)
        const privateKey = nodeA.genPrivateKey('masterPrivateKey', Buffer.from(masterSeed))
        const [lowValue, highValue] = nodeA.implementConditions(-1.0, 1.0, privateKey)
        const [obfuscatedPacket] = nodeA.obfuscateData(Buffer.from(testData), privateKey, lowValue, highValue, 0.0)

        // Obfuscated packet should not resemble original, but should have the same values
        assert.notDeepEqual(obfuscatedPacket, testData)
        const sortedObf = Array.from(obfuscatedPacket).sort()
        const sortedOriginal = Array.from(testData).sort()
        console.log(sortedObf)
        console.log(sortedOriginal)
        assert.deepEqual(sortedObf, sortedOriginal)

        // Recovered packet should be exactly the same as the original
        const [recoveredPacket] = nodeA.obfuscateData(obfuscatedPacket, privateKey, lowValue, highValue, 0.5)
        let recoveredArray = new Uint8Array(recoveredPacket)
        assert.deepEqual(recoveredArray, testData)

        // Attempt to recover the original with a failed condition should lead to a different array
        const [recoveredPacketFalse] = nodeA.obfuscateData(obfuscatedPacket, privateKey, lowValue, highValue, 10.0)
        assert.notDeepEqual(recoveredPacketFalse, testData)
    })
})

describe('Full Process Tests', () => {
    test('twoWayDecryptionEStyle', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB] = ic.distributeData(publicData, 'E', 2)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        const agentPacket = ic.encryptNode(packetB, 'agent')

        // Decrypt the data
        const decryptedData = ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket)
        assert.deepEqual(decryptedData, testData)
    })

    test('twoWayDecryptionKStyle', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB] = ic.distributeData(publicData, 'K', 2)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        const agentPacket = ic.encryptNode(packetB, 'agent')

        // Decrypt the data
        const decryptedData = ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket)
        assert.deepEqual(decryptedData, testData)
    })

    test('threeWayDecryptionEStyle', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB, packetC] = ic.distributeData(publicData, 'E', 3)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        const agentPacket = ic.encryptNode(packetB, 'agent')
        const targetPacket = ic.encryptNode(packetC, 'target')

        // Decrypt the data
        const decryptedData = ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket)
        assert.deepEqual(decryptedData, testData)
    })

    test('threeWayDecryptionKStyle', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB, packetC] = ic.distributeData(publicData, 'K', 3)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        const agentPacket = ic.encryptNode(packetB, 'agent')
        const targetPacket = ic.encryptNode(packetC, 'target')

        // Decrypt the data
        const decryptedData = ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket)
        assert.deepEqual(decryptedData, testData)
    })

    test('publicKeyDecryptionFailure', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB, packetC] = ic.distributeData(publicData, 'K', 3)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        let agentPacket = ic.encryptNode(packetB, 'agent')
        const targetPacket = ic.encryptNode(packetC, 'target')

        // Now modify one of the public keys
        const decryptNode = new ic.DecryptNode('')
        const agentData = decryptNode.unpackageData(agentPacket)
        const agentPublicKey = new Uint8Array(agentData.publicKey)
        const modAgentPublicKey = new Uint8Array(agentPublicKey)
        modAgentPublicKey[0] = agentPublicKey[1]
        modAgentPublicKey[1] = agentPublicKey[0]

        const encryptNode = new ic.EncryptNode('')
        const modifiedAgentPacket: ic.EmbeddingDict = {
            embedding: Buffer.from(agentData.packet),
            privateKey: new Uint8Array(agentData.privateKey),
            publicKey: modAgentPublicKey,
            identity: agentData.identity,
        }

        agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity)

        // Decrypt the data
        try {
            const decryptedData = ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket)
            assert.notDeepEqual(decryptedData, testData)
        } catch (e) {
            console.log(`Recovery failed: ${e}`)
            return
        }
    })

    test('publicKeyDecryptionCatastrophicFailure2', () => {
        const testData = new Uint8Array(600)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB] = ic.distributeData(publicData, 'K', 2)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        let agentPacket = ic.encryptNode(packetB, 'agent')

        // Now modify one of the public keys
        const decryptNode = new ic.DecryptNode('')
        const agentData = decryptNode.unpackageData(agentPacket)
        const setupNode = new ic.SetupNode('__')
        const encryptNode = new ic.EncryptNode('')

        const modifiedAgentPacket: ic.EmbeddingDict = {
            embedding: Buffer.from(agentData.packet),
            privateKey: new Uint8Array(agentData.privateKey),
            publicKey: new Uint8Array(setupNode.genPublicKey(Buffer.from(crypto.randomBytes(32)))),
            identity: agentData.identity,
        }

        agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity)

        // Decrypt the data
        assert.throws(() => {
            ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket)
        })
    })

    test('publicKeyDecryptionCatastrophicFailure3', () => {
        const testData = new Uint8Array(600)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB, packetC] = ic.distributeData(publicData, 'E', 3)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        let agentPacket = ic.encryptNode(packetB, 'agent')
        const targetPacket = ic.encryptNode(packetC, 'Domain')

        // Now modify one of the public keys
        const decryptNode = new ic.DecryptNode('')
        const agentData = decryptNode.unpackageData(agentPacket)
        const setupNode = new ic.SetupNode('__')
        const encryptNode = new ic.EncryptNode('')

        const modifiedAgentPacket: ic.EmbeddingDict = {
            embedding: Buffer.from(agentData.packet),
            privateKey: new Uint8Array(agentData.privateKey),
            publicKey: new Uint8Array(setupNode.genPublicKey(Buffer.from(crypto.randomBytes(32)))),
            identity: agentData.identity
        }

        agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity)

        // Decrypt the data
        assert.throws(() => {
            ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket)
        })
    })

    test('keyCycling', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB, packetC] = ic.distributeData(publicData, 'E', 3)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        const agentPacket = ic.encryptNode(packetB, 'agent')
        const targetPacket = ic.encryptNode(packetC, 'target')
        const cycledAgentPacket = ic.cycleKey(agentPacket, 'agent')

        // Decrypt the data
        const decryptedData = ic.decryptNode(privateData, 1.0, false, authPacket, cycledAgentPacket, targetPacket)

        assert.deepEqual(decryptedData, testData)
    })

    test('privateKeyDecryptionFailure3', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB, packetC] = ic.distributeData(publicData, 'K', 3)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        let agentPacket = ic.encryptNode(packetB, 'agent')
        const targetPacket = ic.encryptNode(packetC, 'target')

        // Now modify one of the private keys
        const decryptNode = new ic.DecryptNode('')
        const agentData = decryptNode.unpackageData(agentPacket)
        const agentPrivateKey = new Uint8Array(agentData.privateKey)
        const modAgentPrivateKey = new Uint8Array(agentPrivateKey)
        modAgentPrivateKey[0] = agentPrivateKey[1]
        modAgentPrivateKey[1] = agentPrivateKey[0]

        const encryptNode = new ic.EncryptNode('')
        const modifiedAgentPacket: ic.EmbeddingDict = {
            embedding: Buffer.from(agentData.packet),
            privateKey: modAgentPrivateKey,
            publicKey: new Uint8Array(agentData.publicKey),
            identity: agentData.identity
        }

        agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity)

        // Decrypt the data
        const decryptedData = ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket, targetPacket)
        assert.notDeepEqual(decryptedData, testData)
    })

    test('privateKeyDecryptionFailure2', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB] = ic.distributeData(publicData, 'E', 2)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        let agentPacket = ic.encryptNode(packetB, 'agent')

        // Now modify one of the private keys
        const decryptNode = new ic.DecryptNode('')
        const agentData = decryptNode.unpackageData(agentPacket)
        const agentPrivateKey = new Uint8Array(agentData.privateKey)
        const modAgentPrivateKey = new Uint8Array(agentPrivateKey)
        modAgentPrivateKey[0] = agentPrivateKey[1]
        modAgentPrivateKey[1] = agentPrivateKey[0]

        const encryptNode = new ic.EncryptNode('')
        const modifiedAgentPacket: ic.EmbeddingDict = {
            embedding: Buffer.from(agentData.packet),
            privateKey: modAgentPrivateKey,
            publicKey: new Uint8Array(agentData.publicKey),
            identity: agentData.identity
        }

        agentPacket = encryptNode.packageData(modifiedAgentPacket, agentData.mode, agentData.identity)

        // Decrypt the data
        const decryptedData = ic.decryptNode(privateData, 1.0, false, authPacket, agentPacket)
        assert.notDeepEqual(decryptedData, testData)
    })

    test('conditionFailure3', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB, packetC] = ic.distributeData(publicData, 'E', 3)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        const agentPacket = ic.encryptNode(packetB, 'agent')
        const targetPacket = ic.encryptNode(packetC, 'target')

        // Decrypt the data
        const decryptedData = ic.decryptNode(privateData, -1.0, false, authPacket, agentPacket, targetPacket)
        assert.notDeepEqual(decryptedData, testData)
    })

    test('conditionFailure2', () => {
        const testData = new Uint8Array(300)
        crypto.randomFillSync(testData)

        // Setup the network
        const [publicData, privateData] = ic.setupNode(testData, 0.0, 10.0)
        const [packetA, packetB] = ic.distributeData(publicData, 'E', 2)

        // Encrypt the portions
        const authPacket = ic.encryptNode(packetA, 'authoriser')
        const agentPacket = ic.encryptNode(packetB, 'agent')

        // Decrypt the data
        const decryptedData = ic.decryptNode(privateData, 11.0, false, authPacket, agentPacket)
        assert.notDeepEqual(decryptedData, testData)
    })
})
