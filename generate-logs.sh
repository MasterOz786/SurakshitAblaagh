#!/bin/bash
# Generate all required logs for Requirements 6, 7, 8
# Run this script to generate logs for screenshots

echo "=== GENERATING ALL SECURITY LOGS ==="
echo ""

# Check if server is running
if ! curl -s http://localhost:3000/health > /dev/null 2>&1; then
    echo "ERROR: Server is not running!"
    echo "Please start the server first: npm start"
    exit 1
fi

echo "1. AUTHENTICATION ATTEMPTS (Requirement 8)"
echo "-------------------------------------------"
echo "Registering user alice..."
curl -s -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq '.' 2>/dev/null || \
curl -s -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
echo ""

echo "Login successful..."
curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq '.' 2>/dev/null || \
curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
echo ""

echo "Failed login attempt..."
curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"wrongpass"}' | jq '.' 2>/dev/null || \
curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"wrongpass"}'
echo ""
echo ""

echo "2. KEY EXCHANGE ATTEMPTS (Requirement 8)"
echo "-------------------------------------------"
echo "Registering E2EE users..."
curl -s -X POST http://localhost:3000/api/e2ee/register \
  -H "Content-Type: application/json" \
  -d '{"userId":"alice","publicKey":[1,2,3,4,5]}' | jq '.' 2>/dev/null || \
curl -s -X POST http://localhost:3000/api/e2ee/register \
  -H "Content-Type: application/json" \
  -d '{"userId":"alice","publicKey":[1,2,3,4,5]}'
echo ""

curl -s -X POST http://localhost:3000/api/e2ee/register \
  -H "Content-Type: application/json" \
  -d '{"userId":"bob","publicKey":[6,7,8,9,10]}' | jq '.' 2>/dev/null || \
curl -s -X POST http://localhost:3000/api/e2ee/register \
  -H "Content-Type: application/json" \
  -d '{"userId":"bob","publicKey":[6,7,8,9,10]}'
echo ""

echo "Initiating key exchange..."
curl -s -X POST http://localhost:3000/api/e2ee/key-exchange/initiate \
  -H "Content-Type: application/json" \
  -d '{"senderId":"alice","receiverId":"bob"}' | jq '.' 2>/dev/null || \
curl -s -X POST http://localhost:3000/api/e2ee/key-exchange/initiate \
  -H "Content-Type: application/json" \
  -d '{"senderId":"alice","receiverId":"bob"}' | head -c 200
echo ""
echo ""

echo "3. REPLAY ATTACK TEST (Requirement 6)"
echo "-------------------------------------------"
node test-replay-attack.js 2>&1
echo ""

echo "4. MITM ATTACK TEST (Requirement 7)"
echo "-------------------------------------------"
node test-mitm-attack.js 2>&1
echo ""

echo "5. SECURITY LOG FILE"
echo "-------------------------------------------"
if [ -f security.log ]; then
    echo "Last 30 lines of security.log:"
    tail -30 security.log
else
    echo "security.log not found - logs are in server console"
    echo "Check /tmp/server-logs.log or server terminal output"
fi

echo ""
echo "=== ALL LOGS GENERATED ==="
echo "Take screenshots of:"
echo "  1. Terminal output above"
echo "  2. security.log file (if exists)"
echo "  3. Server console output"
echo "  4. Replay attack test results"
echo "  5. MITM attack test results"

