/**
 * E2EE Cryptography Module
 * Pure JavaScript implementation - NO Node.js crypto module
 * Uses Web Crypto API patterns for client-side compatibility
 */

// AES-GCM encryption/decryption (pure JavaScript implementation)
// This is a simplified version - full AES-GCM would require extensive implementation
export function encryptAESGCM(plaintext, key, iv) {
  // For client-side: Use Web Crypto API
  // For backend: Pure JavaScript AES-GCM implementation needed
  // This is a placeholder structure - actual implementation would be complex
  
  // Convert inputs to proper formats
  const plaintextBuffer = typeof plaintext === 'string' 
    ? new TextEncoder().encode(plaintext) 
    : plaintext;
  
  // XOR cipher as a simple example (NOT secure - needs full AES implementation)
  // In production, implement full AES-256-GCM in JavaScript
  const encrypted = xorEncrypt(plaintextBuffer, key);
  
  // Generate auth tag (simplified - real GCM needs GHASH)
  const authTag = generateAuthTag(encrypted, key, iv);
  
  return {
    encrypted: encrypted,
    iv: iv,
    authTag: authTag
  };
}

export function decryptAESGCM(encryptedData, key, iv, authTag) {
  // Verify auth tag first
  const expectedTag = generateAuthTag(encryptedData, key, iv);
  if (!constantTimeEquals(authTag, expectedTag)) {
    throw new Error('Authentication failed - invalid auth tag');
  }
  
  // Decrypt
  const decrypted = xorEncrypt(encryptedData, key); // XOR is reversible
  
  return typeof decrypted === 'string' ? decrypted : new TextDecoder().decode(decrypted);
}

// Simple XOR encryption (NOT secure - placeholder for full AES implementation)
function xorEncrypt(data, key) {
  const result = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ key[i % key.length];
  }
  return result;
}

// Generate authentication tag (simplified - real GCM uses GHASH)
function generateAuthTag(data, key, iv) {
  // Simple HMAC-like tag generation
  // In production, implement proper GHASH for GCM mode
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    hash = ((hash << 5) - hash) + data[i];
    hash = hash & hash; // Convert to 32bit integer
  }
  for (let i = 0; i < key.length; i++) {
    hash = ((hash << 5) - hash) + key[i];
    hash = hash & hash;
  }
  for (let i = 0; i < iv.length; i++) {
    hash = ((hash << 5) - hash) + iv[i];
    hash = hash & hash;
  }
  
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tag[i] = (hash >>> (i * 2)) & 0xFF;
  }
  return tag;
}

// Constant-time comparison to prevent timing attacks
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

// Key derivation using HKDF (pure JavaScript implementation)
export function deriveKey(sharedSecret, salt, info) {
  // HKDF implementation in pure JavaScript
  // Extract phase: PRK = HMAC-SHA256(salt, sharedSecret)
  const prk = hmacSHA256(salt || new Uint8Array(32), sharedSecret);
  
  // Expand phase
  const infoBuffer = typeof info === 'string' 
    ? new TextEncoder().encode(info) 
    : info || new Uint8Array(0);
  
  const okm = new Uint8Array(32); // Output key material (256 bits for AES-256)
  
  let t = new Uint8Array(0);
  let counter = 1;
  
  for (let i = 0; i < okm.length; i += 32) {
    const hmacInput = new Uint8Array(t.length + infoBuffer.length + 1);
    hmacInput.set(t, 0);
    hmacInput.set(infoBuffer, t.length);
    hmacInput[hmacInput.length - 1] = counter;
    
    t = hmacSHA256(prk, hmacInput);
    
    const copyLength = Math.min(32, okm.length - i);
    okm.set(t.slice(0, copyLength), i);
    counter++;
  }
  
  return okm;
}

// HMAC-SHA256 implementation (pure JavaScript)
function hmacSHA256(key, message) {
  // Simplified HMAC - in production, use full SHA-256 implementation
  // This is a placeholder that demonstrates the structure
  const blockSize = 64; // SHA-256 block size
  
  // Pad key to block size
  const keyPadded = new Uint8Array(blockSize);
  if (key.length > blockSize) {
    // Hash key if too long
    const keyHash = simpleHash(key);
    keyPadded.set(keyHash.slice(0, blockSize), 0);
  } else {
    keyPadded.set(key, 0);
  }
  
  // Create inner and outer pads
  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = keyPadded[i] ^ 0x36;
    opad[i] = keyPadded[i] ^ 0x5C;
  }
  
  // Inner hash
  const innerInput = new Uint8Array(blockSize + message.length);
  innerInput.set(ipad, 0);
  innerInput.set(message, blockSize);
  const innerHash = simpleHash(innerInput);
  
  // Outer hash
  const outerInput = new Uint8Array(blockSize + innerHash.length);
  outerInput.set(opad, 0);
  outerInput.set(innerHash, blockSize);
  const outerHash = simpleHash(outerInput);
  
  return outerHash;
}

// Simple hash function (placeholder - needs full SHA-256 implementation)
function simpleHash(data) {
  // This is a simplified hash - in production, implement full SHA-256
  let hash = new Uint8Array(32);
  let accumulator = 0;
  
  for (let i = 0; i < data.length; i++) {
    accumulator = ((accumulator << 8) + data[i]) % 2147483647;
    hash[i % 32] = (hash[i % 32] + accumulator) & 0xFF;
  }
  
  // Mix the hash
  for (let i = 0; i < 32; i++) {
    hash[i] = (hash[i] ^ hash[(i + 1) % 32] ^ hash[(i + 2) % 32]) & 0xFF;
  }
  
  return hash;
}

// Generate random IV for AES-GCM (using Web Crypto API or Math.random fallback)
export function generateIV() {
  // Use Web Crypto API if available (browser)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const iv = new Uint8Array(12); // 96 bits for GCM
    crypto.getRandomValues(iv);
    return iv;
  }
  
  // Fallback: Math.random (NOT cryptographically secure, but works for demo)
  const iv = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    iv[i] = Math.floor(Math.random() * 256);
  }
  return iv;
}

// Generate random salt for key derivation
export function generateSalt() {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    return salt;
  }
  
  const salt = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    salt[i] = Math.floor(Math.random() * 256);
  }
  return salt;
}
