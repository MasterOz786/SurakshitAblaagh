/**
 * Generate Network Traffic for Wireshark Capture
 * This script generates HTTP traffic that can be captured in Wireshark
 * to demonstrate replay attacks and MITM attacks
 */

import http from 'http';

const SERVER_URL = 'http://localhost:3000';
const API_BASE = `${SERVER_URL}/api/e2ee`;

// Helper to make HTTP requests
function makeRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, body });
      });
    });
    
    req.on('error', reject);
    
    if (data) {
      req.write(JSON.stringify(data));
    }
    
    req.end();
  });
}

async function demonstrateReplayAttack() {
  console.log('='.repeat(70));
  console.log('GENERATING TRAFFIC FOR REPLAY ATTACK DEMONSTRATION');
  console.log('='.repeat(70));
  console.log('\n1. Registering users...');
  
  // Register users
  await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/e2ee/register',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    userId: 'alice',
    publicKey: Array.from(new Uint8Array(65).fill(1))
  });
  
  await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/e2ee/register',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    userId: 'bob',
    publicKey: Array.from(new Uint8Array(65).fill(2))
  });
  
  console.log('   ✓ Users registered');
  
  console.log('\n2. Initiating key exchange...');
  const keyExchangeRes = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/e2ee/key-exchange/initiate',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    senderId: 'alice',
    receiverId: 'bob'
  });
  
  console.log('   ✓ Key exchange initiated');
  const keyData = JSON.parse(keyExchangeRes.body);
  
  console.log('\n3. Sending first legitimate message...');
  const message1 = {
    type: 'e2ee-message',
    senderId: 'alice',
    receiverId: 'bob',
    timestamp: Date.now(),
    nonce: Array.from(new Uint8Array(16).fill(1)),
    sequenceNumber: 1,
    iv: Array.from(new Uint8Array(12).fill(1)),
    encryptedPayload: Array.from(new Uint8Array(32).fill(1)),
    authTag: Array.from(new Uint8Array(16).fill(1))
  };
  
  const sendRes1 = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/e2ee/message/send',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    senderId: 'alice',
    receiverId: 'bob',
    message: 'Hello Bob'
  });
  
  console.log(`   ✓ First message sent (Status: ${sendRes1.status})`);
  
  console.log('\n4. Attempting to replay the same message...');
  console.log('   → This will be captured in Wireshark');
  console.log('   → Look for HTTP POST with same nonce and sequence number');
  
  // Wait a moment for Wireshark to capture
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  const replayRes = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/e2ee/message/receive',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    receiverId: 'bob',
    encryptedMessage: message1  // Replay the same message
  });
  
  console.log(`   ✓ Replay attempt made (Status: ${replayRes.status})`);
  console.log('   → Check Wireshark for the rejection response');
  
  console.log('\n' + '='.repeat(70));
  console.log('REPLAY ATTACK TRAFFIC GENERATED');
  console.log('='.repeat(70));
  console.log('\nIn Wireshark, look for:');
  console.log('  1. First POST to /api/e2ee/message/send (legitimate message)');
  console.log('  2. Second POST to /api/e2ee/message/receive (replay attempt)');
  console.log('  3. HTTP 400 response with "Replay attack detected"');
}

async function demonstrateMITMAttack() {
  console.log('\n' + '='.repeat(70));
  console.log('GENERATING TRAFFIC FOR MITM ATTACK DEMONSTRATION');
  console.log('='.repeat(70));
  
  console.log('\n1. Key exchange WITHOUT signature (vulnerable)...');
  const keyExchange1 = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/e2ee/key-exchange/initiate',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    senderId: 'alice',
    receiverId: 'bob'
  });
  
  console.log(`   ✓ Key exchange initiated (Status: ${keyExchange1.status})`);
  console.log('   → In Wireshark: Look for POST with ephemeralPublicKey (no signature)');
  
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  console.log('\n2. Key exchange WITH signature (protected)...');
  const keyData = JSON.parse(keyExchange1.body);
  
  const keyExchange2 = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/e2ee/key-exchange/complete',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    senderId: 'alice',
    receiverId: 'bob',
    ephemeralPublicKey: keyData.ephemeralPublicKey,
    keyExchangeMessage: {
      ephemeralPublicKey: keyData.ephemeralPublicKey,
      timestamp: Date.now(),
      senderId: 'alice'
    },
    signature: Array.from(new Uint8Array(32).fill(123)) // Valid signature
  });
  
  console.log(`   ✓ Key exchange with signature (Status: ${keyExchange2.status})`);
  console.log('   → In Wireshark: Look for POST with signature field');
  
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  console.log('\n3. Attempting key exchange with INVALID signature...');
  const keyExchange3 = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/e2ee/key-exchange/complete',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    senderId: 'alice',
    receiverId: 'bob',
    ephemeralPublicKey: Array.from(new Uint8Array(65).fill(999)), // Modified key
    keyExchangeMessage: {
      ephemeralPublicKey: Array.from(new Uint8Array(65).fill(999)), // Modified
      timestamp: Date.now(),
      senderId: 'alice'
    },
    signature: Array.from(new Uint8Array(32).fill(123)) // Original signature (won't match)
  });
  
  console.log(`   ✓ Invalid signature attempt (Status: ${keyExchange3.status})`);
  console.log('   → In Wireshark: Look for HTTP 400 response with "signature verification failed"');
  
  console.log('\n' + '='.repeat(70));
  console.log('MITM ATTACK TRAFFIC GENERATED');
  console.log('='.repeat(70));
  console.log('\nIn Wireshark, look for:');
  console.log('  1. Key exchange without signature (vulnerable)');
  console.log('  2. Key exchange with valid signature (protected)');
  console.log('  3. Key exchange with invalid signature (rejected)');
}

// Main execution
async function main() {
  console.log('\n🚀 Starting Wireshark Traffic Generation');
  console.log('📡 Make sure Wireshark is capturing on loopback (lo0) interface');
  console.log('🔍 Filter: tcp.port == 3000 && http\n');
  
  try {
    // Check if server is running
    const healthCheck = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/health',
      method: 'GET'
    });
    
    if (healthCheck.status !== 200) {
      throw new Error('Server not running. Start with: node src/index.js');
    }
    
    console.log('✓ Server is running\n');
    
    await demonstrateReplayAttack();
    await new Promise(resolve => setTimeout(resolve, 2000));
    await demonstrateMITMAttack();
    
    console.log('\n✅ All traffic generated!');
    console.log('📸 Now take screenshots from Wireshark');
    
  } catch (error) {
    console.error('\n❌ Error:', error.message);
    console.error('\nMake sure:');
    console.error('  1. Server is running: node src/index.js');
    console.error('  2. Wireshark is capturing on loopback interface');
    console.error('  3. Filter is set to: tcp.port == 3000 && http');
  }
}

main();

