/**
 * Constants and default values for the SurakshitAblaagh package.
 */

import { KeyType, KeyLength } from './keys.js';

// Default certificate lifetime: 3 months
export const DefaultCertLifeTime = 90 * 24 * 60 * 60 * 1000; // milliseconds

// Default key type and length
export const DefaultKeyType = KeyType.EC;
export const DefaultKeyLength = KeyLength.EC256;

// Service name size for hashing
export const serviceNameSize = 8;

// Error definitions
export class ErrKeyConfigNotCompatible extends Error {
  constructor() {
    super('the key type and key size are not compatible');
    this.name = 'ErrKeyConfigNotCompatible';
  }
}

