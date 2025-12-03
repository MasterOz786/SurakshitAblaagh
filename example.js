/**
 * Example usage of E2EE Messaging System
 */

import { 
  generateECDHKeyPair,
  initiateKeyExchange,
  completeKeyExchange,
  deriveSessionKey,
  generateSalt
} from './src/e2ee/keyExchange.js';

import {
  encryptMessage,
  decryptMessage
} from './src/e2ee/message.js';

import {
  encryptFile,
  decryptFile
} from './src/e2ee/fileHandler.js';

import {
  simulateMITMAttack
} from './src/attacks/mitm.js';

import {
  simulateReplayAttack
} from './src/attacks/replay.js';

// Example: Key Exchange
async function exampleKeyExchange() {
  console.log('=== Key Exchange Example ===\n');

  // User A generates key pair
  const userA = generateECDHKeyPair();
  console.log('User A: Key pair generated');

  // User B generates key pair
  const userB = generateECDHKeyPair();
  console.log('User B: Key pair generated\n');

  // User A initiates key exchange with User B's public key
  const keyExchange = initiateKeyExchange(userB.publicKey);
  console.log('User A: Key exchange initiated');
  console.log(`Ephemeral public key: ${keyExchange.ephemeralPublicKey.length} bytes\n`);

  // User B completes key exchange
  const sharedSecret = completeKeyExchange(
    keyExchange.ephemeralPublicKey,
    userB.privateKey
  );
  console.log('User B: Key exchange completed');
  console.log(`Shared secret: ${sharedSecret.length} bytes\n`);

  // Derive session key
  const salt = generateSalt();
  const sessionKey = deriveSessionKey(
    sharedSecret,
    salt,
    'userA-userB-session'
  );
  console.log('Session key derived');
  console.log(`Session key: ${sessionKey.length} bytes\n`);

  return sessionKey;
}

// Example: Message Encryption
async function exampleMessageEncryption(sessionKey) {
  console.log('=== Message Encryption Example ===\n');

  const plaintext = 'Hello, this is a secret message!';
  console.log(`Original message: ${plaintext}\n`);

  // Encrypt message
  const encrypted = encryptMessage(
    plaintext,
    sessionKey,
    'userA',
    'userB'
  );
  console.log('Message encrypted');
  console.log(`Encrypted payload: ${encrypted.encryptedPayload.length} bytes`);
  console.log(`IV: ${encrypted.iv.length} bytes`);
  console.log(`Auth tag: ${encrypted.authTag.length} bytes\n`);

  // Decrypt message
  const decrypted = decryptMessage(encrypted, sessionKey);
  console.log('Message decrypted');
  console.log(`Decrypted message: ${decrypted.plaintext}\n`);

  return encrypted;
}

// Example: File Encryption
async function exampleFileEncryption(sessionKey) {
  console.log('=== File Encryption Example ===\n');

  const fileData = new TextEncoder().encode('This is a test file content');
  console.log(`Original file size: ${fileData.length} bytes\n`);

  // Encrypt file
  const encrypted = encryptFile(fileData, sessionKey, 'test.txt');
  console.log('File encrypted');
  console.log(`Number of chunks: ${encrypted.chunks.length}`);
  console.log(`Total encrypted size: ${encrypted.chunks.reduce((sum, c) => sum + c.encryptedData.length, 0)} bytes\n`);

  // Decrypt file
  const decrypted = decryptFile(encrypted, sessionKey);
  console.log('File decrypted');
  console.log(`Decrypted file size: ${decrypted.size} bytes`);
  console.log(`File content: ${new TextDecoder().decode(decrypted.data)}\n`);
}

// Example: Attack Simulation
async function exampleAttackSimulation() {
  console.log('=== Attack Simulation Examples ===\n');

  // MITM Attack
  console.log('1. MITM Attack Simulation:');
  const legitimateKey = new Uint8Array(65).fill(1);
  const attackerKey = new Uint8Array(65).fill(2);
  const mitmResult = simulateMITMAttack(legitimateKey, attackerKey);
  console.log(`Result: ${mitmResult.attackSuccessful ? 'Attack succeeded' : 'Attack prevented'}\n`);

  // Replay Attack
  console.log('2. Replay Attack Simulation:');
  const message = {
    type: 'message',
    senderId: 'userA',
    receiverId: 'userB',
    timestamp: Date.now(),
    nonce: [1, 2, 3, 4, 5],
    encryptedPayload: [1, 2, 3],
    iv: [1, 2, 3],
    authTag: [1, 2, 3]
  };
  const nonceTracker = new Set();
  const replayResult = simulateReplayAttack(message, nonceTracker);
  console.log(`Result: ${replayResult.attackSuccessful ? 'Attack succeeded' : 'Attack prevented'}\n`);
}

// Run examples
async function runExamples() {
  try {
    const sessionKey = await exampleKeyExchange();
    await exampleMessageEncryption(sessionKey);
    await exampleFileEncryption(sessionKey);
    await exampleAttackSimulation();
    
    console.log('=== All Examples Completed ===');
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runExamples();
}

export { runExamples };

