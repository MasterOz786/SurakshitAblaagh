/**
 * Key pair generation and management for RSA, EC, and Ed25519.
 * Uses Node's crypto module (allowed for backend digital signatures).
 */

import crypto from 'crypto';

export const KeyType = {
  ED25519: 'ed25519 Elliptic Curve',
  RSA: 'RSA',
  EC: 'NIST Elliptic Curve',
};

export const KeyLength = {
  ED25519: 'EC 25519',
  RSA2048: 'RSA 2048',
  RSA3072: 'RSA 3072',
  RSA4096: 'RSA 4096',
  RSA8192: 'RSA 8192',
  EC256: 'EC 256',
  EC384: 'EC 384',
  EC521: 'EC 521',
};

export function newKeyPair(keyType, keyLength) {
  switch (keyType) {
    case KeyType.ED25519:
      return newEd25519();
    case KeyType.EC:
      return newEc(keyLength);
    case KeyType.RSA:
      return newRSA(keyLength);
    default:
      throw new Error(`the given type is not valid: ${keyType}`);
  }
}

export function newRSA(keyLength) {
  const lengthMap = {
    [KeyLength.RSA2048]: 2048,
    [KeyLength.RSA3072]: 3072,
    [KeyLength.RSA4096]: 4096,
    [KeyLength.RSA8192]: 8192,
  };

  const length = lengthMap[keyLength];
  if (!length) {
    throw new Error(`invalid RSA key length: ${keyLength}`);
  }

  // Use Node's crypto module (allowed for backend)
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: length,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return {
    type: KeyType.RSA,
    length: keyLength,
    privateKeyPEM: privateKey,
    publicKeyPEM: publicKey,
    privateKey: crypto.createPrivateKey(privateKey),
    publicKey: crypto.createPublicKey(publicKey),
  };
}

export function newEc(keyLength) {
  const curveMap = {
    [KeyLength.EC256]: 'prime256v1',
    [KeyLength.EC384]: 'secp384r1',
    [KeyLength.EC521]: 'secp521r1',
  };

  const curve = curveMap[keyLength];
  if (!curve) {
    throw new Error(`invalid EC key length: ${keyLength}`);
  }

  // Use Node's crypto module (allowed for backend)
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: curve,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return {
    type: KeyType.EC,
    length: keyLength,
    privateKeyPEM: privateKey,
    publicKeyPEM: publicKey,
    privateKey: crypto.createPrivateKey(privateKey),
    publicKey: crypto.createPublicKey(publicKey),
  };
}

export function newEd25519() {
  // Use Node's crypto module (allowed for backend)
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return {
    type: KeyType.ED25519,
    length: KeyLength.ED25519,
    privateKeyPEM: privateKey,
    publicKeyPEM: publicKey,
    privateKey: crypto.createPrivateKey(privateKey),
    publicKey: crypto.createPublicKey(publicKey),
  };
}

export function getPrivateDER(keyPair) {
  // Export private key as DER
  return keyPair.privateKey.export({
    format: 'der',
    type: 'pkcs8'
  });
}

export function getPrivatePEM(keyPair) {
  return keyPair.privateKeyPEM;
}

export function getPublicPEM(keyPair) {
  return keyPair.publicKeyPEM;
}

export function marshal(keyPair) {
  const exportData = {
    Type: keyPair.type,
    Length: keyPair.length,
    Private: getPrivateDER(keyPair).toString('hex'),
  };
  return Buffer.from(JSON.stringify(exportData));
}

export function unmarshalKeyPair(input) {
  const exportData = JSON.parse(input.toString());
  const keyType = exportData.Type;
  const keyLength = exportData.Length;
  const privateDER = Buffer.from(exportData.Private, 'hex');

  const privateKey = crypto.createPrivateKey({
    key: privateDER,
    format: 'der',
    type: 'pkcs8'
  });

  const publicKey = crypto.createPublicKey(privateKey);

  return {
    type: keyType,
    length: keyLength,
    privateKeyPEM: privateKey.export({ format: 'pem', type: 'pkcs8' }),
    publicKeyPEM: publicKey.export({ format: 'pem', type: 'spki' }),
    privateKey,
    publicKey,
  };
}
