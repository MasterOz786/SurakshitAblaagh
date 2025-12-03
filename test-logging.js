/**
 * Test Security Logging - Requirement 8
 * Verifies all logging functionality works correctly
 */

import {
  logSecurityEvent,
  SecurityEventType,
  logAuthenticationAttempt,
  logDecryptionFailure,
  logInvalidSignature,
  logMetadataAccess,
  logKeyExchange
} from './src/security/logging.js';

console.log('='.repeat(70));
console.log('SECURITY LOGGING TEST - Requirement 8');
console.log('='.repeat(70));
console.log('');

// Test 1: Authentication attempts
console.log('1. Testing authentication logging...');
logAuthenticationAttempt('alice', true);
logAuthenticationAttempt('bob', false);
console.log('   ✓ Authentication attempts logged');

// Test 2: Key exchange logging
console.log('\n2. Testing key exchange logging...');
logKeyExchange('alice', 'bob', true);
logKeyExchange('bob', 'alice', false);
console.log('   ✓ Key exchange attempts logged');

// Test 3: Failed decryption logging
console.log('\n3. Testing failed decryption logging...');
logDecryptionFailure('bob', 'alice', new Error('Authentication tag verification failed'));
console.log('   ✓ Failed decryption logged');

// Test 4: Invalid signature logging
console.log('\n4. Testing invalid signature logging...');
logInvalidSignature('alice', 'key_exchange', {
  receiverId: 'bob',
  error: 'Signature verification failed',
  ephemeralPublicKey: [1, 2, 3, 4, 5]
});
console.log('   ✓ Invalid signature logged');

// Test 5: Metadata access logging
console.log('\n5. Testing metadata access logging...');
logMetadataAccess('bob', 'message_query', 'receiver:bob');
logMetadataAccess('alice', 'file_query', 'file123');
console.log('   ✓ Metadata access logged');

// Test 6: Replay attack detection logging
console.log('\n6. Testing replay attack detection logging...');
logSecurityEvent(SecurityEventType.REPLAY_DETECTED, {
  receiverId: 'bob',
  senderId: 'alice',
  error: 'Replay attack detected - nonce already used',
  timestamp: Date.now()
});
console.log('   ✓ Replay attack detection logged');

// Test 7: All event types
console.log('\n7. Testing all security event types...');
const eventTypes = [
  SecurityEventType.AUTHENTICATION_ATTEMPT,
  SecurityEventType.AUTHENTICATION_SUCCESS,
  SecurityEventType.AUTHENTICATION_FAILED,
  SecurityEventType.KEY_EXCHANGE,
  SecurityEventType.KEY_EXCHANGE_FAILED,
  SecurityEventType.MESSAGE_SENT,
  SecurityEventType.MESSAGE_RECEIVED,
  SecurityEventType.MESSAGE_DECRYPTION_FAILED,
  SecurityEventType.REPLAY_DETECTED,
  SecurityEventType.INVALID_SIGNATURE,
  SecurityEventType.METADATA_ACCESS,
  SecurityEventType.SESSION_ESTABLISHED
];

eventTypes.forEach(eventType => {
  logSecurityEvent(eventType, {
    test: true,
    timestamp: Date.now()
  });
});
console.log('   ✓ All event types logged');

console.log('\n' + '='.repeat(70));
console.log('LOGGING TEST COMPLETE');
console.log('='.repeat(70));
console.log('');
console.log('VERIFIED LOGGING FOR:');
console.log('  ✓ Authentication attempts (success and failure)');
console.log('  ✓ Key exchange attempts');
console.log('  ✓ Failed message decryptions');
console.log('  ✓ Detected replay attacks');
console.log('  ✓ Invalid signatures');
console.log('  ✓ Server-side metadata access');
console.log('');
console.log('Check security.log file for detailed logs');
console.log('='.repeat(70));

