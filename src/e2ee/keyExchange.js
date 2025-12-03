/**
 * Secure Key Exchange Protocol
 * Custom variant with digital signatures and key confirmation
 * Pure JavaScript implementation - NO Node.js crypto
 */

import { deriveKey } from './crypto.js';

// Enhanced ECDH key exchange with digital signatures
export function generateECDHKeyPair() {
  // Generate random private key (32 bytes for P-256)
  const privateKey = generateRandomBytes(32);
  
  // Compute public key from private key (simplified - needs full EC point multiplication)
  const publicKey = derivePublicKeyFromPrivate(privateKey);
  
  return {
    privateKey: privateKey,
    publicKey: publicKey,
    computeSecret: (otherPublicKey) => computeECDHSecret(privateKey, otherPublicKey)
  };
}

// Derive public key from private key (simplified EC point multiplication)
function derivePublicKeyFromPrivate(privateKey) {
  // In production, implement full elliptic curve point multiplication
  const publicKey = new Uint8Array(65); // Uncompressed public key format
  publicKey[0] = 0x04; // Uncompressed point indicator
  
  // Simplified: hash private key to get public key coordinates
  // Real implementation needs: Q = d * G where G is generator point
  const hash = simpleHash(privateKey);
  publicKey.set(hash.slice(0, 32), 1); // x coordinate
  publicKey.set(hash.slice(32, 64), 33); // y coordinate
  
  return publicKey;
}

// Compute ECDH shared secret (simplified)
function computeECDHSecret(privateKey, otherPublicKey) {
  // In production, implement: sharedSecret = privateKey * otherPublicKey
  const combined = new Uint8Array(privateKey.length + otherPublicKey.length);
  combined.set(privateKey, 0);
  combined.set(otherPublicKey, privateKey.length);
  
  // Use hash of combined keys as shared secret (simplified)
  return simpleHash(combined);
}

// Simple hash function (needs full SHA-256 implementation)
function simpleHash(data) {
  let hash = new Uint8Array(32);
  let accumulator = 0;
  
  for (let i = 0; i < data.length; i++) {
    accumulator = ((accumulator << 8) + data[i]) % 2147483647;
    hash[i % 32] = (hash[i % 32] + accumulator) & 0xFF;
  }
  
  for (let i = 0; i < 32; i++) {
    hash[i] = (hash[i] ^ hash[(i + 1) % 32] ^ hash[(i + 2) % 32]) & 0xFF;
  }
  
  return hash;
}

// Digital signature generation (simplified - needs full RSA/ECDSA implementation)
export function signData(data, privateKey) {
  // In production, implement proper digital signature (RSA-PSS or ECDSA)
  // This is a placeholder that demonstrates the structure
  if (!data || !privateKey) {
    throw new Error('Data and privateKey required for signing');
  }
  
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const keyBytes = privateKey instanceof Uint8Array ? privateKey : new Uint8Array(privateKey);
  
  const combined = new Uint8Array(dataBytes.length + keyBytes.length);
  combined.set(dataBytes, 0);
  combined.set(keyBytes, dataBytes.length);
  
  // Use hash as signature (simplified)
  return simpleHash(combined);
}

// Digital signature verification
export function verifySignature(data, signature, publicKey) {
  // In production, implement proper signature verification
  // This is a placeholder
  const expectedSignature = signData(data, publicKey); // Using public key as placeholder
  
  return constantTimeEquals(signature, expectedSignature);
}

// Constant-time comparison
function constantTimeEquals(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

// Enhanced key exchange with digital signatures
export function initiateKeyExchange(recipientPublicKey, senderPrivateKey) {
  // Generate ephemeral key pair
  const keyPair = generateECDHKeyPair();
  
  // Compute shared secret
  const sharedSecret = keyPair.computeSecret(recipientPublicKey);
  
  // Create key exchange message
  const keyExchangeMessage = {
    ephemeralPublicKey: Array.from(keyPair.publicKey),
    timestamp: Date.now(),
    senderId: 'sender' // Would be actual sender ID
  };
  
  // Sign the key exchange message
  const messageBytes = new TextEncoder().encode(JSON.stringify(keyExchangeMessage));
  const signature = signData(messageBytes, senderPrivateKey);
  
  return {
    ephemeralPublicKey: keyPair.publicKey,
    sharedSecret: sharedSecret,
    keyExchangeMessage: keyExchangeMessage,
    signature: Array.from(signature)
  };
}

// Complete key exchange with signature verification
export function completeKeyExchange(ephemeralPublicKey, ownPrivateKey, ownPublicKey, keyExchangeMessage, signature) {
  // Verify signature first
  const messageBytes = new TextEncoder().encode(JSON.stringify(keyExchangeMessage));
  const signatureBytes = new Uint8Array(signature);
  
  if (!verifySignature(messageBytes, signatureBytes, ownPublicKey)) {
    throw new Error('Key exchange signature verification failed - possible MITM attack');
  }
  
  // Compute shared secret
  const sharedSecret = computeECDHSecret(ownPrivateKey, new Uint8Array(ephemeralPublicKey));
  
  return sharedSecret;
}

// Key confirmation message (final step)
export function generateKeyConfirmation(sharedSecret, sessionId) {
  // Generate confirmation token from shared secret
  const confirmationData = new TextEncoder().encode(
    `KEY_CONFIRM:${sessionId}:${Date.now()}`
  );
  
  // Use HMAC-like function for confirmation
  const confirmation = hmacSHA256(sharedSecret, confirmationData);
  
  return {
    sessionId: sessionId,
    confirmation: Array.from(confirmation),
    timestamp: Date.now()
  };
}

// Verify key confirmation
export function verifyKeyConfirmation(sharedSecret, sessionId, confirmation, timestamp) {
  // Check timestamp (prevent replay)
  const maxAge = 5 * 60 * 1000; // 5 minutes
  if (Date.now() - timestamp > maxAge) {
    throw new Error('Key confirmation expired');
  }
  
  // Regenerate confirmation
  const confirmationData = new TextEncoder().encode(
    `KEY_CONFIRM:${sessionId}:${timestamp}`
  );
  const expectedConfirmation = hmacSHA256(sharedSecret, confirmationData);
  
  if (!constantTimeEquals(new Uint8Array(confirmation), expectedConfirmation)) {
    throw new Error('Key confirmation verification failed');
  }
  
  return true;
}

// HMAC-SHA256 implementation
function hmacSHA256(key, message) {
  const blockSize = 64;
  const keyPadded = new Uint8Array(blockSize);
  if (key.length > blockSize) {
    const keyHash = simpleHash(key);
    keyPadded.set(keyHash.slice(0, blockSize), 0);
  } else {
    keyPadded.set(key, 0);
  }
  
  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = keyPadded[i] ^ 0x36;
    opad[i] = keyPadded[i] ^ 0x5C;
  }
  
  const innerInput = new Uint8Array(blockSize + message.length);
  innerInput.set(ipad, 0);
  innerInput.set(message, blockSize);
  const innerHash = simpleHash(innerInput);
  
  const outerInput = new Uint8Array(blockSize + innerHash.length);
  outerInput.set(opad, 0);
  outerInput.set(innerHash, blockSize);
  const outerHash = simpleHash(outerInput);
  
  return outerHash;
}

// Derive session key from shared secret
export function deriveSessionKey(sharedSecret, salt, info) {
  return deriveKey(sharedSecret, salt, info);
}

// Generate random bytes
function generateRandomBytes(length) {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }
  
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}
