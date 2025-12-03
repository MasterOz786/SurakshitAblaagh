/**
 * Digital Signatures using Web Crypto API
 * ECDSA signatures for key exchange authentication
 */

// Sign data with private key
export async function signData(data, privateKey) {
  // Import private key
  const key = await crypto.subtle.importKey(
    'pkcs8',
    privateKey,
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    false,
    ['sign']
  );

  // Sign with timestamp
  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    key,
    data
  );

  return new Uint8Array(signature);
}

// Verify signature with public key
export async function verifySignature(data, signature, publicKey) {
  // Import public key
  const key = await crypto.subtle.importKey(
    'spki',
    publicKey,
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    false,
    ['verify']
  );

  // Verify signature
  const isValid = await crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    key,
    signature,
    data
  );

  return isValid;
}

