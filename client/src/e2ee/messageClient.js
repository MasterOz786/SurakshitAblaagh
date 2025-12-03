/**
 * Client-Side Message Encryption/Decryption
 * Unique message structure - all encryption client-side
 */

import { encryptAESGCM, decryptAESGCM, generateIV, generateNonce } from '../crypto/webCrypto.js';

// Message sequence counter (client-side only)
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

// Unique message structure
export async function encryptMessage(plaintext, sessionKey, senderId, receiverId) {
  // Generate fresh IV (unpredictable and non-repeating)
  const iv = generateIV();
  
  // Convert plaintext to bytes
  const plaintextBytes = new TextEncoder().encode(plaintext);
  
  // Encrypt with AES-256-GCM (client-side only)
  const encrypted = await encryptAESGCM(plaintextBytes, sessionKey, iv);
  
  // Get sequence number
  const sequenceNumber = incrementMessageCounter(senderId, receiverId);
  
  // Generate nonce for replay protection
  const nonce = generateNonce();
  
  // Unique message structure
  const message = {
    version: '1.0',
    type: 'e2ee-message',
    senderId: senderId,
    receiverId: receiverId,
    timestamp: Date.now(),
    nonce: Array.from(nonce),
    sequenceNumber: sequenceNumber,
    iv: Array.from(iv),
    encryptedPayload: Array.from(encrypted.encrypted),
    authTag: Array.from(encrypted.authTag)
  };
  
  // NO plaintext in message structure
  return message;
}

// Decrypt message (client-side only)
export async function decryptMessage(encryptedMessage, sessionKey) {
  const encryptedData = new Uint8Array(encryptedMessage.encryptedPayload);
  const iv = new Uint8Array(encryptedMessage.iv);
  const authTag = new Uint8Array(encryptedMessage.authTag);
  
  // Decrypt with AES-GCM (client-side only)
  const decrypted = await decryptAESGCM(encryptedData, sessionKey, iv, authTag);
  
  // Convert to string
  const plaintext = new TextDecoder().decode(decrypted);
  
  return {
    senderId: encryptedMessage.senderId,
    receiverId: encryptedMessage.receiverId,
    timestamp: encryptedMessage.timestamp,
    sequenceNumber: encryptedMessage.sequenceNumber,
    plaintext: plaintext
  };
}

// Verify message (replay protection)
export function verifyMessage(message, nonceTracker) {
  // Check timestamp (5-minute window)
  const maxAge = 5 * 60 * 1000;
  const age = Date.now() - message.timestamp;
  if (age > maxAge || age < 0) {
    throw new Error('Message timestamp invalid - possible replay attack');
  }
  
  // Check nonce (replay protection)
  const nonceStr = JSON.stringify(message.nonce);
  if (nonceTracker.has(nonceStr)) {
    throw new Error('Replay attack detected - nonce already used');
  }
  nonceTracker.add(nonceStr);
  
  // Check sequence number
  const senderKey = `${message.senderId}-${message.receiverId}`;
  const lastSeq = messageCounters.get(senderKey) || 0;
  if (message.sequenceNumber <= lastSeq) {
    throw new Error(`Replay attack detected - sequence number ${message.sequenceNumber} <= last ${lastSeq}`);
  }
  
  return true;
}
