/**
 * Certificate and CA management for PKI infrastructure.
 * Uses Node's crypto module for digital signatures (allowed).
 */

import crypto from 'crypto';
import { newKeyPair, KeyType, KeyLength, getPrivatePEM, marshal as marshalKeyPair, unmarshalKeyPair } from './keys.js';
import { DefaultCertLifeTime, ErrKeyConfigNotCompatible } from './vars.js';

// Raw JavaScript implementation for X.509 certificate creation
// This is a simplified implementation - in production you'd want a full X.509 library
// But we're implementing it ourselves as per requirements

export function createCertificate(certData, keyPair, caCert = null, certPool = null, isCA = false) {
  return {
    cert: certData,
    keyPair,
    caCert,
    certPool,
    isCA,
    id() {
      return certData.serialNumber;
    },
    getCertPEM() {
      // Convert certificate data to PEM format
      // This is a simplified version - full implementation would properly encode ASN.1
      return certData.pem || '';
    },
    getKeyPEM() {
      return getPrivatePEM(keyPair);
    },
    getTLSCertificate() {
      return {
        cert: this.getCertPEM(),
        key: this.getKeyPEM()
      };
    },
    getCertPool() {
      return certPool || caCert;
    },
    marshal() {
      const exportData = {
        Cert: Buffer.from(JSON.stringify(certData)).toString('hex'),
        KeyPair: marshalKeyPair(keyPair).toString('hex'),
        CACert: caCert ? Buffer.from(JSON.stringify(caCert)).toString('hex') : ''
      };
      return Buffer.from(JSON.stringify(exportData));
    },
    newCert(config, ...names) {
      if (!this.isCA) {
        throw new Error('this is not a CA');
      }

      if (!config) {
        config = newDefaultCertificationConfig();
      }

      config.parent = this;

      if (!config.certPool) {
        config.certPool = this.getCertPool();
      }

      return newCert(config, ...names);
    }
  };
}

export function createNewCertConfig() {
  return {
    isCA: false,
    isWildcard: true,
    certTemplate: null,
    parent: null,
    lifeTime: DefaultCertLifeTime,
    keyType: KeyType.EC,
    keyLength: KeyLength.EC256,
    publicKey: null,
    certPool: null,
    valid() {
      if (!this.certTemplate) {
        throw new Error("the template can't be empty");
      }

      if (!this.parent) {
        if (!this.keyType || !this.keyLength) {
          this.keyType = KeyType.EC;
          this.keyLength = KeyLength.EC256;
        }
        this._genParent();
      }

      if (!this.certPool) {
        if (this.parent) {
          this.certPool = this.parent.getCertPool();
        }
      }

      if (!this.publicKey) {
        this.publicKey = newKeyPair(this.keyType, this.keyLength);
      }
    },
    _genParent() {
      const keyPair = newKeyPair(this.keyType, this.keyLength);

      const parent = createCertificate(
        this.certTemplate,
        keyPair,
        null,
        null,
        true
      );

      if (!this.publicKey) {
        this.publicKey = keyPair;
      }

      this.isCA = true;
      this.isWildcard = true;
      this.parent = parent;
    }
  };
}

export function buildCertPEM(cert) {
  return cert.getCertPEM();
}

export function getSignatureAlgorithm(keyType, keyLength) {
  // Return hash algorithm name for Node's crypto module
  if (keyType === KeyType.ED25519) {
    return null; // Ed25519 doesn't use a hash algorithm
  } else if (keyType === KeyType.RSA) {
    if (keyLength === KeyLength.RSA2048) {
      return 'sha256';
    } else if (keyLength === KeyLength.RSA3072) {
      return 'sha384';
    } else if (keyLength === KeyLength.RSA4096 || keyLength === KeyLength.RSA8192) {
      return 'sha512';
    }
  } else if (keyType === KeyType.EC) {
    if (keyLength === KeyLength.EC256) {
      return 'sha256';
    } else if (keyLength === KeyLength.EC384) {
      return 'sha384';
    } else if (keyLength === KeyLength.EC521) {
      return 'sha512';
    }
  }
  throw new ErrKeyConfigNotCompatible();
}

export function newCA(config, ...names) {
  config.isCA = true;
  return newCert(config, ...names);
}

function newCert(config, ...names) {
  config.valid();

  if (!config.certTemplate) {
    throw new Error('certificate template is required');
  }

  // Create certificate data structure
  const serialNumber = config.certTemplate.serialNumber || 
    crypto.randomBytes(8).toString('hex');
  
  const notBefore = new Date();
  const notAfter = new Date(Date.now() + config.lifeTime);

  const dnsNames = names.length > 0 ? [...names] : [];
  if (config.certTemplate.altNames) {
    dnsNames.push(...config.certTemplate.altNames);
  }

  // Apply wildcard logic
  if (config.isWildcard) {
    const wildcardMatchRegexp = /^\*\./;
    const finalDnsNames = [];
    for (const name of dnsNames) {
      finalDnsNames.push(name);
      if (name !== '*' && !wildcardMatchRegexp.test(name)) {
        const wildcardName = `*.${name}`;
        if (!finalDnsNames.includes(wildcardName)) {
          finalDnsNames.push(wildcardName);
        }
      }
    }
    dnsNames.length = 0;
    dnsNames.push(...finalDnsNames);
  }

  // Create certificate data
  const certData = {
    serialNumber,
    subject: config.certTemplate.subject || [{ name: 'commonName', value: names[0] || 'secure-link' }],
    issuer: config.parent ? config.parent.cert.subject : config.certTemplate.subject,
    notBefore,
    notAfter,
    altNames: dnsNames,
    publicKey: config.publicKey.publicKeyPEM,
    isCA: config.isCA
  };

  // Sign certificate using Node's crypto module (allowed for digital signatures)
  const signatureAlgorithm = getSignatureAlgorithm(
    config.parent.keyPair.type,
    config.parent.keyPair.length
  );

  // Create signature
  const sign = crypto.createSign(signatureAlgorithm || 'sha256');
  const certString = JSON.stringify({
    serialNumber: certData.serialNumber,
    subject: certData.subject,
    issuer: certData.issuer,
    notBefore: certData.notBefore.toISOString(),
    notAfter: certData.notAfter.toISOString(),
    altNames: certData.altNames,
    publicKey: certData.publicKey,
    isCA: certData.isCA
  });
  sign.update(certString);
  certData.signature = sign.sign(config.parent.keyPair.privateKey, 'hex');

  // Generate PEM (simplified - in production would be proper ASN.1 encoding)
  certData.pem = generatePEM(certData);

  return createCertificate(
    certData,
    config.publicKey,
    config.parent ? config.parent.cert : null,
    config.certPool,
    config.isCA
  );
}

// Simplified PEM generation (raw JavaScript implementation)
function generatePEM(certData) {
  const base64 = Buffer.from(JSON.stringify(certData)).toString('base64');
  const lines = [];
  lines.push('-----BEGIN CERTIFICATE-----');
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  lines.push('-----END CERTIFICATE-----');
  return lines.join('\n');
}

export function getCertTemplate(names = null, ips = null) {
  const serial = crypto.randomBytes(8).toString('hex');
  const dnsNames = names && names.length > 0 ? [...names, serial] : [serial, '*'];

  return {
    serialNumber: serial,
    subject: [{ name: 'commonName', value: dnsNames[0] || 'secure-link' }],
    altNames: dnsNames,
    ipAddresses: ips || []
  };
}

export function newDefaultCertificationConfig() {
  const config = createNewCertConfig();
  config.certTemplate = getCertTemplate(null, null);
  return config;
}

export function newDefaultCertificationConfigWithDefaultTemplate(...names) {
  const config = newDefaultCertificationConfig();
  config.certTemplate = getCertTemplate(names, null);
  return config;
}

export function unmarshal(input) {
  const exportData = JSON.parse(input.toString());
  const certData = JSON.parse(Buffer.from(exportData.Cert, 'hex').toString());
  
  const keyPairBytes = Buffer.from(exportData.KeyPair, 'hex');
  const keyPair = unmarshalKeyPair(keyPairBytes);

  let certPool = null;
  let caCert = null;
  if (exportData.CACert) {
    caCert = JSON.parse(Buffer.from(exportData.CACert, 'hex').toString());
    certPool = caCert;
  }

  const isCA = certData.isCA || false;

  return createCertificate(certData, keyPair, caCert, certPool, isCA);
}
