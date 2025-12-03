/**
 * Replay Attack Simulator
 * Demonstrates how the protocol prevents replay attacks
 */

// Simulate replay attack
export function simulateReplayAttack(originalMessage, nonceTracker) {
  console.log('=== Replay Attack Simulation ===');
  
  // Scenario: Attacker captures and replays a message
  const replayedMessage = {
    ...originalMessage,
    timestamp: originalMessage.timestamp // Same timestamp
  };

  // First attempt (legitimate)
  try {
    verifyMessageReplay(originalMessage, nonceTracker);
    console.log('✓ First message accepted (legitimate)');
  } catch (error) {
    console.log('✗ First message rejected:', error.message);
  }

  // Replay attempt
  try {
    verifyMessageReplay(replayedMessage, nonceTracker);
    console.log('✗ Replay attack SUCCEEDED (should not happen)');
    return {
      attackSuccessful: true,
      warning: 'Replay protection failed'
    };
  } catch (error) {
    console.log('✓ Replay attack PREVENTED:', error.message);
    return {
      attackSuccessful: false,
      reason: error.message,
      prevention: 'Nonce tracking and timestamp validation'
    };
  }
}

// Verify message with replay protection (replay.js version)
export function verifyMessageReplay(message, nonceTracker) {
  // Check timestamp (prevent old messages)
  const maxAge = 5 * 60 * 1000; // 5 minutes
  const age = Date.now() - message.timestamp;
  
  if (age > maxAge) {
    throw new Error('Message too old - possible replay attack');
  }

  if (age < 0) {
    throw new Error('Message from future - invalid timestamp');
  }

  // Check nonce (prevent replay attacks)
  const nonceStr = JSON.stringify(message.nonce);
  if (nonceTracker.has(nonceStr)) {
    throw new Error('Replay attack detected - nonce already used');
  }
  
  // Add nonce to tracker
  nonceTracker.add(nonceStr);

  // Clean old nonces (keep last 1000)
  if (nonceTracker.size > 1000) {
    const first = nonceTracker.values().next().value;
    nonceTracker.delete(first);
  }

  return true;
}

// Demonstrate timestamp validation
export function demonstrateTimestampValidation(message) {
  console.log('=== Timestamp Validation Demonstration ===');
  
  const now = Date.now();
  const messageTime = message.timestamp;
  const age = now - messageTime;
  const maxAge = 5 * 60 * 1000; // 5 minutes

  console.log(`Message timestamp: ${new Date(messageTime).toISOString()}`);
  console.log(`Current time: ${new Date(now).toISOString()}`);
  console.log(`Message age: ${Math.floor(age / 1000)} seconds`);

  if (age > maxAge) {
    console.log('✗ Message REJECTED: Too old (possible replay)');
    return { valid: false, reason: 'Message too old' };
  }

  if (age < 0) {
    console.log('✗ Message REJECTED: From future (invalid)');
    return { valid: false, reason: 'Invalid timestamp' };
  }

  console.log('✓ Message ACCEPTED: Timestamp valid');
  return { valid: true, age: age };
}

// Demonstrate nonce tracking
export function demonstrateNonceTracking(message, nonceTracker) {
  console.log('=== Nonce Tracking Demonstration ===');
  
  const nonceStr = JSON.stringify(message.nonce);
  console.log(`Message nonce: ${nonceStr.substring(0, 20)}...`);

  if (nonceTracker.has(nonceStr)) {
    console.log('✗ Nonce REJECTED: Already seen (replay attack)');
    return { valid: false, reason: 'Nonce already used' };
  }

  nonceTracker.add(nonceStr);
  console.log('✓ Nonce ACCEPTED: New nonce');
  console.log(`Total tracked nonces: ${nonceTracker.size}`);
  
  return { valid: true, tracked: true };
}

// Simulate multiple replay attempts
export function simulateMultipleReplays(originalMessage, attempts = 5) {
  console.log('=== Multiple Replay Attempts Simulation ===');
  
  const nonceTracker = new Set();
  const results = [];

  // First legitimate message
  try {
    verifyMessageReplay(originalMessage, nonceTracker);
    results.push({ attempt: 0, success: true, type: 'legitimate' });
    console.log('Attempt 0 (legitimate): ACCEPTED');
  } catch (error) {
    results.push({ attempt: 0, success: false, error: error.message });
  }

  // Replay attempts
  for (let i = 1; i <= attempts; i++) {
    const replayedMessage = {
      ...originalMessage,
      timestamp: originalMessage.timestamp
    };

    try {
      verifyMessageReplay(replayedMessage, nonceTracker);
      results.push({ attempt: i, success: true, type: 'replay' });
      console.log(`Attempt ${i} (replay): ACCEPTED (should not happen)`);
    } catch (error) {
      results.push({ attempt: i, success: false, type: 'replay', error: error.message });
      console.log(`Attempt ${i} (replay): REJECTED - ${error.message}`);
    }
  }

  const successfulReplays = results.filter(r => r.success && r.type === 'replay').length;
  
  return {
    totalAttempts: attempts + 1,
    successfulReplays: successfulReplays,
    prevented: successfulReplays === 0,
    results: results
  };
}

