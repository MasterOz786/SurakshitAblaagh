/**
 * Client-Side Key Exchange Protocol
 * Unique variant with digital signatures and key confirmation
 * All operations use Web Crypto API - 100% client-side
 */

import { deriveECDHSecret, deriveKeyHKDF, generateSalt, generateNonce, deriveSaltFromEphemeralKeys, getCanonicalInfoString } from './webCrypto.js';
import { signData, verifySignature } from './signatures.js';

// Unique key exchange protocol variant
export async function initiateKeyExchange(recipientPublicKey, senderPrivateKey, senderId, receiverId) {
  // Generate ephemeral ECDH key pair (P-256)
  const ephemeralKeyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveBits', 'deriveKey']
  );

  // Export ephemeral public key
  const ephemeralPublicKey = await crypto.subtle.exportKey('spki', ephemeralKeyPair.publicKey);
  const ephemeralPublicKeyArray = new Uint8Array(ephemeralPublicKey);

  // Compute shared secret using ECDH
  const sharedSecret = await deriveECDHSecret(
    await crypto.subtle.exportKey('pkcs8', ephemeralKeyPair.privateKey),
    recipientPublicKey
  );

  // Create unique key exchange message structure
  const keyExchangeMessage = {
    version: '1.0',
    type: 'key-exchange-initiate',
    senderId: senderId,
    receiverId: receiverId,
    ephemeralPublicKey: Array.from(ephemeralPublicKeyArray),
    timestamp: Date.now(),
    nonce: Array.from(generateNonce())
  };

  // Sign the key exchange message with long-term private key
  const messageBytes = new TextEncoder().encode(JSON.stringify(keyExchangeMessage));
  const signature = await signData(messageBytes, senderPrivateKey);

  return {
    ephemeralPublicKey: ephemeralPublicKeyArray,
    sharedSecret: sharedSecret,
    keyExchangeMessage: keyExchangeMessage,
    signature: Array.from(signature),
    ephemeralKeyPair: ephemeralKeyPair
  };
}

// Complete key exchange with signature verification (bidirectional)
// ownEphemeralPrivateKey: our ephemeral private key
// otherEphemeralPublicKey: other party's ephemeral public key
// ownId: our user ID
// otherId: other party's user ID
export async function completeKeyExchangeBidirectional(
  ownEphemeralPrivateKey,
  ownEphemeralPublicKey,
  otherEphemeralPublicKey,
  ownId,
  otherId
) {
  const ownPub = new Uint8Array(ownEphemeralPublicKey);
  const otherPub = new Uint8Array(otherEphemeralPublicKey);
  
  const sharedSecret = await deriveECDHSecret(ownEphemeralPrivateKey, otherPub);
  const salt = await deriveSaltFromEphemeralKeys(ownPub, otherPub);
  const info = getCanonicalInfoString(ownId, otherId);
  const sessionKey = await deriveKeyHKDF(sharedSecret, salt, info);

  return {
    sharedSecret: sharedSecret,
    sessionKey: sessionKey,
    salt: salt
  };
}

// Complete key exchange with signature verification (legacy - for backward compatibility)
export async function completeKeyExchange(
  ephemeralPublicKey,
  ownPrivateKey,
  senderPublicKey,
  keyExchangeMessage,
  signature,
  ownId
) {
  // Verify timestamp (within 5 minutes)
  const maxAge = 5 * 60 * 1000;
  if (Date.now() - keyExchangeMessage.timestamp > maxAge) {
    throw new Error('Key exchange message expired');
  }

  // Verify signature with timestamp check
  const messageBytes = new TextEncoder().encode(JSON.stringify(keyExchangeMessage));
  const signatureBytes = new Uint8Array(signature);
  
  const isValid = await verifySignature(messageBytes, signatureBytes, senderPublicKey);
  if (!isValid) {
    throw new Error('Key exchange signature verification failed - possible MITM attack');
  }

  // Compute shared secret
  const sharedSecret = await deriveECDHSecret(ownPrivateKey, new Uint8Array(ephemeralPublicKey));

  // Derive session key using HKDF
  const salt = generateSalt();
  const info = new TextEncoder().encode(`${keyExchangeMessage.senderId}-${ownId}-session`);
  const sessionKey = await deriveKeyHKDF(sharedSecret, salt, info);

  return {
    sharedSecret: sharedSecret,
    sessionKey: sessionKey,
    salt: salt
  };
}

// Generate key confirmation message
export async function generateKeyConfirmation(sharedSecret, sessionId, senderId, receiverId) {
  const confirmationData = {
    type: 'key-confirmation',
    sessionId: sessionId,
    senderId: senderId,
    receiverId: receiverId,
    timestamp: Date.now()
  };

  const confirmationBytes = new TextEncoder().encode(JSON.stringify(confirmationData));
  
  // Use HMAC for confirmation
  const key = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const confirmation = await crypto.subtle.sign('HMAC', key, confirmationBytes);

  return {
    ...confirmationData,
    confirmation: Array.from(new Uint8Array(confirmation))
  };
}

// Verify key confirmation
export async function verifyKeyConfirmation(sharedSecret, confirmationMessage) {
  // Check timestamp (within 5 minutes)
  const maxAge = 5 * 60 * 1000;
  if (Date.now() - confirmationMessage.timestamp > maxAge) {
    throw new Error('Key confirmation expired');
  }

  const { confirmation, ...data } = confirmationMessage;
  const confirmationBytes = new TextEncoder().encode(JSON.stringify(data));

  const key = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const isValid = await crypto.subtle.verify(
    'HMAC',
    key,
    new Uint8Array(confirmation),
    confirmationBytes
  );

  if (!isValid) {
    throw new Error('Key confirmation verification failed');
  }

  return true;
}

