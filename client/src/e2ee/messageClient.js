/**
 * Client-Side Message Encryption/Decryption
 * Unique message structure - all encryption client-side
 */

import { encryptAESGCM, decryptAESGCM, generateIV, generateNonce } from '../crypto/webCrypto.js';

// Message sequence counter for SENT messages (client-side only)
let messageCounters = new Map();

// Last received sequence numbers for RECEIVED messages (separate tracking)
let lastReceivedSequenceNumbers = new Map();

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

export function getLastReceivedSequence(senderId, receiverId) {
  const key = `${senderId}-${receiverId}`;
  return lastReceivedSequenceNumbers.get(key) || 0;
}

function setLastReceivedSequence(senderId, receiverId, sequenceNumber) {
  const key = `${senderId}-${receiverId}`;
  const current = getLastReceivedSequence(senderId, receiverId);
  // Only update if new sequence is higher (prevent downgrade)
  if (sequenceNumber > current) {
    lastReceivedSequenceNumbers.set(key, sequenceNumber);
  }
}

// Reset sequence number tracking for a sender-receiver pair (useful when re-establishing session)
export function resetLastReceivedSequence(senderId, receiverId) {
  const key = `${senderId}-${receiverId}`;
  lastReceivedSequenceNumbers.delete(key);
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

// Verify message (replay protection) - ONLY call this for RECEIVED messages
// skipTimestampCheck: set to true when loading messages from database (they're not replays, just old messages)
// skipSequenceCheck: set to true when retrying old messages that failed decryption before
export function verifyMessage(message, nonceTracker, skipTimestampCheck = false, skipSequenceCheck = false) {
  // Check timestamp (5-minute window) - skip for loaded messages from database
  if (!skipTimestampCheck) {
    const maxAge = 10 * 60 * 1000; // 10 minutes for real-time messages
    const age = Date.now() - message.timestamp;
    if (age > maxAge || age < 0) {
      throw new Error('Message timestamp invalid - possible replay attack');
    }
  } else {
    // For loaded messages, still check that timestamp is reasonable (not from future, not too old)
    // Allow up to 7 days for loaded messages (reasonable for offline message delivery)
    const maxAgeForLoaded = 7 * 24 * 60 * 60 * 1000; // 7 days
    const age = Date.now() - message.timestamp;
    if (age > maxAgeForLoaded || age < -60000) { // Allow 1 minute clock skew
      throw new Error('Message timestamp invalid - message too old or from future');
    }
  }
  
  // Check nonce (replay protection)
  const nonceStr = JSON.stringify(message.nonce);
  if (nonceTracker.has(nonceStr)) {
    throw new Error('Replay attack detected - nonce already used');
  }
  nonceTracker.add(nonceStr);
  
  // Check sequence number (for RECEIVED messages only)
  // Skip this check when retrying old messages that failed decryption before
  if (!skipSequenceCheck) {
    const lastSeq = getLastReceivedSequence(message.senderId, message.receiverId);
    if (message.sequenceNumber <= lastSeq) {
      throw new Error(`Replay attack detected - sequence number ${message.sequenceNumber} <= last ${lastSeq}`);
    }
    
    // Update last received sequence number
    setLastReceivedSequence(message.senderId, message.receiverId, message.sequenceNumber);
  } else {
    // For retries, still update sequence number if this one is higher (to prevent accepting even older replays)
    const lastSeq = getLastReceivedSequence(message.senderId, message.receiverId);
    if (message.sequenceNumber > lastSeq) {
      setLastReceivedSequence(message.senderId, message.receiverId, message.sequenceNumber);
    }
  }
  
  return true;
}
