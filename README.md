# SurakshitAblaagh - End-to-End Encrypted Messaging System

A secure communication system providing end-to-end encryption (E2EE) for text messaging and file sharing, ensuring that messages and files never exist in plaintext outside the sender or receiver device.

## 🎯 Project Overview

This project implements a complete E2EE messaging system with:
- **Hybrid Cryptography**: Combining asymmetric encryption (RSA/ECC) with symmetric encryption (AES-GCM)
- **Secure Key Exchange**: Custom protocol with digital signatures and key confirmation
- **Attack Prevention**: MITM and replay attack protection
- **Security Analysis**: Comprehensive threat modeling using STRIDE framework

## 🔐 Security Features

- **AES-256-GCM Encryption**: All messages encrypted with fresh IV per message
- **Perfect Forward Secrecy**: Ephemeral keys for each session
- **Replay Protection**: Nonces, timestamps, and sequence numbers
- **MITM Prevention**: Digital signatures in key exchange
- **Client-Side Only Decryption**: Server never sees plaintext
- **Secure Key Storage**: IndexedDB on client, private keys never leave device

## 📋 Requirements

### Backend
- Node.js 18+ 
- MongoDB (optional, for metadata storage)

### Frontend
- Modern browser with Web Crypto API support
- React 18+

## 🚀 Setup Instructions

### Backend Setup

1. Install dependencies:
```bash
npm install
```

2. Set environment variables (optional):
```bash
export MONGODB_URI=mongodb://localhost:27017
export DB_NAME=securelink_e2ee
export PORT=3000
```

3. Start the server:
```bash
node src/app.js
```

The server will run on `http://localhost:3000`

### Frontend Setup

1. Navigate to client directory:
```bash
cd client
npm install
```

2. Start development server:
```bash
npm run dev
```

The client will run on `http://localhost:5173`

## 📁 Project Structure

```
securelink/
├── src/                    # Backend (Node.js/Express)
│   ├── auth/              # User authentication
│   │   ├── auth.js        # Password hashing & user management
│   │   └── routes.js      # Auth API routes
│   ├── e2ee/              # E2EE core modules
│   │   ├── api.js         # E2EE API routes
│   │   ├── crypto.js      # AES-GCM encryption (pure JS)
│   │   ├── keyExchange.js # Key exchange protocol
│   │   ├── message.js     # Message encryption/decryption
│   │   └── fileHandler.js # File encryption
│   ├── attacks/           # Attack simulators
│   │   ├── mitm.js        # MITM attack demo
│   │   └── replay.js      # Replay attack demo
│   ├── security/          # Security logging & analysis
│   │   ├── logging.js     # Security event logging
│   │   └── threatModel.js # STRIDE threat modeling
│   ├── db/                # Database integration
│   │   └── mongodb.js     # MongoDB operations
│   └── app.js             # Express server
├── client/                # Frontend (React)
│   ├── src/
│   │   ├── components/    # React components
│   │   │   ├── Login.jsx  # Login/Register UI
│   │   │   └── Chat.jsx   # Chat interface
│   │   ├── crypto/        # Web Crypto API wrapper
│   │   │   └── webCrypto.js
│   │   ├── storage/       # Client-side key storage
│   │   │   └── keyStorage.js
│   │   └── e2ee/          # Client-side E2EE
│   │       └── messageClient.js
└── README.md
```

## 🔑 Key Exchange Protocol

### Protocol Flow

1. **Registration**: Users register with public keys
2. **Key Exchange Initiation**: 
   - Sender generates ephemeral key pair
   - Computes shared secret using ECDH
   - Signs key exchange message
3. **Key Exchange Completion**:
   - Receiver verifies signature
   - Computes shared secret
   - Derives session key using HKDF
4. **Key Confirmation**:
   - Both parties exchange confirmation messages
   - Verify session establishment

### Security Properties

- **Authenticity**: Digital signatures prevent MITM
- **Forward Secrecy**: Ephemeral keys ensure PFS
- **Key Confirmation**: Final step ensures mutual authentication

## 🛡️ Threat Model (STRIDE)

### Identified Threats

1. **Man-in-the-Middle (MITM)**: Mitigated by digital signatures
2. **Replay Attacks**: Mitigated by nonces, timestamps, sequence numbers
3. **Eavesdropping**: Mitigated by E2EE encryption
4. **Key Compromise**: Mitigated by key rotation and PFS
5. **Denial of Service**: Partially mitigated by rate limiting
6. **Unauthorized Access**: Mitigated by authentication

**Security Score: 91.67% (Grade A)**

## 🧪 Testing

### Run Critical Tests

```bash
# Test core crypto functions
node -e "import('./src/e2ee/crypto.js').then(m => { const iv = m.generateIV(); console.log('IV:', iv.length); })"

# Test message encryption
node -e "import('./src/e2ee/message.js').then(m => { const key = new Uint8Array(32).fill(1); const enc = m.encryptMessage('test', key, 'alice', 'bob'); console.log('Encrypted:', enc.encryptedPayload.length > 0); })"

# Test replay protection
node -e "import('./src/e2ee/message.js').then(m => { const tracker = new Set(); const key = new Uint8Array(32).fill(1); const msg = m.encryptMessage('test', key, 'alice', 'bob'); m.verifyMessage(msg, tracker); try { m.verifyMessage(msg, tracker); } catch(e) { console.log('Replay rejected:', e.message); } })"
```

### API Testing

```bash
# Health check
curl http://localhost:3000/health

# Register user
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass123"}'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass123"}'

# E2EE Registration
curl -X POST http://localhost:3000/api/e2ee/register \
  -H "Content-Type: application/json" \
  -d '{"userId":"alice","publicKey":[1,2,3]}'
```

## 📊 Attack Demonstrations

### MITM Attack

Located in `src/attacks/mitm.js`:
- Demonstrates how MITM breaks DH without signatures
- Shows how digital signatures prevent MITM
- Includes logs and evidence

### Replay Attack

Located in `src/attacks/replay.js`:
- Demonstrates replay attack attempt
- Shows detection and prevention mechanisms
- Includes sequence number validation

## 📝 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/user/:username` - Get user info

### E2EE
- `POST /api/e2ee/register` - Register E2EE user
- `POST /api/e2ee/key-exchange/initiate` - Initiate key exchange
- `POST /api/e2ee/key-exchange/complete` - Complete key exchange
- `POST /api/e2ee/key-exchange/confirm` - Confirm key exchange
- `POST /api/e2ee/message/send` - Send encrypted message
- `POST /api/e2ee/message/receive` - Receive encrypted message
- `POST /api/e2ee/file/upload` - Upload encrypted file
- `POST /api/e2ee/file/download` - Download encrypted file

### Security
- `GET /api/security/info` - Get security report
- `GET /health` - Health check

## 🔒 Cryptographic Implementation

### Allowed Technologies
- **Web Crypto API** (client-side)
- **Node.js crypto** (backend digital signatures only)
- **Pure JavaScript** implementations

### Forbidden Technologies
- Third-party E2EE libraries
- Pre-built cryptography wrappers
- CryptoJS for RSA/ECC
- NodeForge

## 📈 Security Logging

All security events are logged:
- Authentication attempts
- Key exchange attempts
- Failed message decryptions
- Detected replay attacks
- Invalid signatures
- Server-side metadata access

## 🎓 Project Deliverables

1. **Full Project Report (PDF)**
   - Introduction & problem statement
   - Threat model (STRIDE)
   - Cryptographic design
   - Key exchange protocol diagrams
   - Attack demonstrations
   - Architecture diagrams
   - Evaluation and conclusion

2. **Working Application**
   - Functional E2EE messaging
   - Encrypted file sharing
   - Replay/disconnect handling
   - Error handling
   - Client-side only decryption

3. **Video Demonstration (10-15 min)**
   - Protocol explanation
   - Working demo
   - MITM attack demo
   - Replay attack demo
   - Limitations discussion

4. **GitHub Repository**
   - Source code (client + server)
   - README with setup instructions
   - Documentation
   - Screenshots of Wireshark/BurpSuite tests

## 👥 Team Contribution

This project requires equal code contribution from all team members. Use Git commits to track contributions.

## 📄 License

This project is for educational purposes only.

## 🙏 Acknowledgments

- Web Crypto API documentation
- STRIDE threat modeling framework
- E2EE best practices
