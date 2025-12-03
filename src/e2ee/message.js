/**
 * E2EE Message Encryption/Decryption
 * Pure JavaScript implementation
 */

import { encryptAESGCM, decryptAESGCM, generateIV, deriveKey, generateSalt } from './crypto.js';
import { deriveSessionKey } from './keyExchange.js';

// Message sequence counter (per user pair)
const messageCounters = new Map();

// Get or create message counter for user pair
function getMessageCounter(senderId, receiverId) {
  const key = `${senderId}-${receiverId}`;
  if (!messageCounters.has(key)) {
    messageCounters.set(key, 0);
  }
  return messageCounters.get(key);
}

// Increment message counter
function incrementMessageCounter(senderId, receiverId) {
  const key = `${senderId}-${receiverId}`;
  const current = getMessageCounter(senderId, receiverId);
  messageCounters.set(key, current + 1);
  return current + 1;
}

// Encrypt a message with E2EE
export function encryptMessage(plaintext, sessionKey, senderId, receiverId) {
  // Generate IV for this message
  const iv = generateIV();
  
  // Encrypt message with AES-GCM
  const encrypted = encryptAESGCM(plaintext, sessionKey, iv);
  
  // Get and increment message sequence number
  const sequenceNumber = incrementMessageCounter(senderId, receiverId);
  
  // Create message structure
  const message = {
    type: 'message',
    senderId: senderId,
    receiverId: receiverId,
    timestamp: Date.now(),
    nonce: generateNonce(), // For replay protection
    sequenceNumber: sequenceNumber, // Message sequence number
    iv: Array.from(iv), // Convert to array for JSON
    encryptedPayload: Array.from(encrypted.encrypted), // Convert to array
    authTag: Array.from(encrypted.authTag) // Convert to array
  };
  
  return message;
}

// Decrypt a message
export function decryptMessage(encryptedMessage, sessionKey) {
  // Reconstruct encrypted data
  const encryptedData = new Uint8Array(encryptedMessage.encryptedPayload);
  const iv = new Uint8Array(encryptedMessage.iv);
  const authTag = new Uint8Array(encryptedMessage.authTag);
  
  // Decrypt
  const plaintext = decryptAESGCM(encryptedData, sessionKey, iv, authTag);
  
  return {
    senderId: encryptedMessage.senderId,
    receiverId: encryptedMessage.receiverId,
    timestamp: encryptedMessage.timestamp,
    nonce: encryptedMessage.nonce,
    plaintext: plaintext
  };
}

// Generate nonce for replay protection
function generateNonce() {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const nonce = new Uint8Array(16);
    crypto.getRandomValues(nonce);
    return Array.from(nonce);
  }
  
  const nonce = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    nonce[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(nonce);
}

// Track last sequence numbers per sender
const lastSequenceNumbers = new Map();

// Verify message integrity and replay protection
export function verifyMessage(message, nonceTracker) {
  // Check timestamp (prevent old messages)
  const maxAge = 5 * 60 * 1000; // 5 minutes
  const age = Date.now() - message.timestamp;
  if (age > maxAge) {
    throw new Error('Message too old - possible replay attack');
  }

  if (age < 0) {
    throw new Error('Message from future - invalid timestamp');
  }
  
  // Check nonce (prevent replay attacks)
  const nonceStr = JSON.stringify(message.nonce);
  if (nonceTracker.has(nonceStr)) {
    throw new Error('Replay attack detected - nonce already used');
  }
  nonceTracker.add(nonceStr);
  
  // Check sequence number (prevent replay and ensure ordering)
  const senderKey = `${message.senderId}-${message.receiverId}`;
  const lastSeq = lastSequenceNumbers.get(senderKey) || 0;
  
  if (message.sequenceNumber <= lastSeq) {
    throw new Error(`Replay attack detected - sequence number ${message.sequenceNumber} <= last ${lastSeq}`);
  }
  
  // Update last sequence number
  lastSequenceNumbers.set(senderKey, message.sequenceNumber);
  
  // Clean old nonces (keep last 1000)
  if (nonceTracker.size > 1000) {
    const first = nonceTracker.values().next().value;
    nonceTracker.delete(first);
  }
  
  return true;
}

