/**
 * Web Crypto API Wrapper
 * Client-side cryptographic operations using Web Crypto API
 */

// Generate RSA key pair using Web Crypto API
export async function generateRSAKeyPair(keySize = 2048) {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: keySize,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: 'SHA-256'
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );

  // Export keys
  const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

  return {
    publicKey: new Uint8Array(publicKey),
    privateKey: new Uint8Array(privateKey),
    keyPair: keyPair // Keep CryptoKey objects for operations
  };
}

// Generate EC key pair using Web Crypto API
export async function generateECKeyPair(namedCurve = 'P-256') {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: namedCurve
    },
    true, // extractable
    ['deriveKey', 'deriveBits']
  );

  // Export keys
  const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

  return {
    publicKey: new Uint8Array(publicKey),
    privateKey: new Uint8Array(privateKey),
    keyPair: keyPair
  };
}

// ECDH key derivation using Web Crypto API
export async function deriveECDHSecret(privateKey, publicKey) {
  // Import keys
  const privateKeyObj = await crypto.subtle.importKey(
    'pkcs8',
    privateKey,
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    false,
    ['deriveBits', 'deriveKey']
  );

  const publicKeyObj = await crypto.subtle.importKey(
    'spki',
    publicKey,
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    false,
    []
  );

  // Derive shared secret
  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: publicKeyObj
    },
    privateKeyObj,
    256 // 256 bits
  );

  return new Uint8Array(sharedSecret);
}

// AES-GCM encryption using Web Crypto API
export async function encryptAESGCM(plaintext, key, iv) {
  // Import key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt']
  );

  // Encrypt
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128
    },
    cryptoKey,
    plaintext
  );

  // Extract ciphertext and auth tag
  const encryptedArray = new Uint8Array(encrypted);
  const authTag = encryptedArray.slice(-16); // Last 16 bytes are auth tag
  const ciphertext = encryptedArray.slice(0, -16);

  return {
    encrypted: ciphertext,
    authTag: authTag,
    iv: iv
  };
}

// AES-GCM decryption using Web Crypto API
export async function decryptAESGCM(encryptedData, key, iv, authTag) {
  // Combine ciphertext and auth tag
  const combined = new Uint8Array(encryptedData.length + authTag.length);
  combined.set(encryptedData, 0);
  combined.set(authTag, encryptedData.length);

  // Import key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['decrypt']
  );

  // Decrypt
  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      cryptoKey,
      combined
    );

    return new Uint8Array(decrypted);
  } catch (error) {
    throw new Error('Decryption failed - authentication tag verification failed');
  }
}

// HKDF key derivation using Web Crypto API
export async function deriveKeyHKDF(sharedSecret, salt, info) {
  // Import shared secret as key
  const baseKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveBits', 'deriveKey']
  );

  // Derive key
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt: salt,
      info: info,
      hash: 'SHA-256'
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );

  // Export derived key
  const exportedKey = await crypto.subtle.exportKey('raw', derivedKey);
  return new Uint8Array(exportedKey);
}

// Generate random IV for AES-GCM
export function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12)); // 96 bits for GCM
}

// Generate random salt
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(32));
}

// Generate random nonce
export function generateNonce() {
  return crypto.getRandomValues(new Uint8Array(16));
}

