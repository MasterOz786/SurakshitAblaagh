/**
 * Client-side message encryption/decryption
 * Uses Web Crypto API
 */

import { encryptAESGCM, decryptAESGCM, generateIV, generateNonce } from '../crypto/webCrypto.js';

// Message sequence counter (client-side)
let messageCounters = new Map();

function getMessageCounter(senderId, receiverId) {
  const key = `${senderId}-${receiverId}`;
  if (!messageCounters.has(key)) {
    messageCounters.set(key, 0);
  }
  return messageCounters.get(key);
}

function incrementMessageCounter(senderId, receiverId) {
  const key = `${senderId}-${receiverId}`;
  const current = getMessageCounter(senderId, receiverId);
  messageCounters.set(key, current + 1);
  return current + 1;
}

// Encrypt message client-side
export async function encryptMessage(plaintext, sessionKey, senderId, receiverId) {
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const iv = generateIV();
  
  // Encrypt with AES-GCM
  const encrypted = await encryptAESGCM(plaintextBytes, sessionKey, iv);
  
  // Get sequence number
  const sequenceNumber = incrementMessageCounter(senderId, receiverId);
  
  return {
    type: 'message',
    senderId: senderId,
    receiverId: receiverId,
    timestamp: Date.now(),
    nonce: Array.from(generateNonce()),
    sequenceNumber: sequenceNumber,
    iv: Array.from(iv),
    encryptedPayload: Array.from(encrypted.encrypted),
    authTag: Array.from(encrypted.authTag)
  };
}

// Decrypt message client-side
export async function decryptMessage(encryptedMessage, sessionKey) {
  const encryptedData = new Uint8Array(encryptedMessage.encryptedPayload);
  const iv = new Uint8Array(encryptedMessage.iv);
  const authTag = new Uint8Array(encryptedMessage.authTag);
  
  // Decrypt
  const decrypted = await decryptAESGCM(encryptedData, sessionKey, iv, authTag);
  
  return {
    senderId: encryptedMessage.senderId,
    receiverId: encryptedMessage.receiverId,
    timestamp: encryptedMessage.timestamp,
    sequenceNumber: encryptedMessage.sequenceNumber,
    plaintext: new TextDecoder().decode(decrypted)
  };
}

