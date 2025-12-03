/**
 * MITM Attack Simulator
 * Demonstrates how the protocol prevents MITM attacks
 */

// Simulate MITM attack attempt
export function simulateMITMAttack(legitimatePublicKey, attackerPublicKey) {
  console.log('=== MITM Attack Simulation ===');
  
  // Scenario: Attacker tries to intercept key exchange
  const attackScenario = {
    step1: 'Attacker intercepts key exchange initiation',
    step2: 'Attacker replaces legitimate public key with their own',
    step3: 'Attacker attempts to establish session with victim',
    prevention: 'Certificate pinning and public key verification prevent this'
  };

  // Simulate interception
  const interceptedKey = attackerPublicKey;
  
  // Check if keys match (certificate pinning check)
  const keysMatch = constantTimeEquals(
    legitimatePublicKey,
    interceptedKey
  );

  if (!keysMatch) {
    console.log('✓ MITM Attack DETECTED: Public keys do not match');
    console.log('✓ Protocol PREVENTS attack by rejecting mismatched keys');
    return {
      attackSuccessful: false,
      reason: 'Public key mismatch detected',
      prevention: 'Certificate pinning and key verification'
    };
  }

  return {
    attackSuccessful: true,
    warning: 'This should not happen with proper certificate pinning'
  };
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

// Demonstrate certificate pinning
export function demonstrateCertificatePinning(userId, expectedPublicKey, receivedPublicKey) {
  console.log('=== Certificate Pinning Demonstration ===');
  
  // In production, this would be stored securely
  const pinnedKeys = new Map();
  pinnedKeys.set(userId, expectedPublicKey);

  const pinnedKey = pinnedKeys.get(userId);
  const keysMatch = constantTimeEquals(
    new Uint8Array(pinnedKey),
    new Uint8Array(receivedPublicKey)
  );

  if (keysMatch) {
    console.log('✓ Certificate pinning: Keys match - connection is legitimate');
    return { verified: true, message: 'Key verified' };
  } else {
    console.log('✗ Certificate pinning: Keys do NOT match - possible MITM attack');
    return { verified: false, message: 'MITM attack detected' };
  }
}

// Simulate key exchange interception
export function simulateKeyExchangeInterception(originalKeyExchange, attackerKey) {
  console.log('=== Key Exchange Interception Simulation ===');
  
  // Attacker tries to replace the public key
  const interceptedExchange = {
    ...originalKeyExchange,
    publicKey: attackerKey
  };

  // Protocol checks: Verify public key matches expected
  const verificationResult = verifyPublicKey(originalKeyExchange.publicKey, attackerKey);
  
  if (!verificationResult.valid) {
    console.log('✓ Attack PREVENTED: Public key verification failed');
    return {
      intercepted: true,
      prevented: true,
      reason: 'Public key verification failed'
    };
  }

  return {
    intercepted: true,
    prevented: false,
    warning: 'Attack would succeed without proper verification'
  };
}

function verifyPublicKey(expected, received) {
  const match = constantTimeEquals(
    new Uint8Array(expected),
    new Uint8Array(received)
  );
  
  return {
    valid: match,
    message: match ? 'Key verified' : 'Key mismatch - possible attack'
  };
}

