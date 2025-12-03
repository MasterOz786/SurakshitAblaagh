# SecureLink - Technical Documentation

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Cryptographic Design](#cryptographic-design)
3. [Key Exchange Protocol](#key-exchange-protocol)
4. [Threat Model](#threat-model)
5. [Attack Demonstrations](#attack-demonstrations)
6. [API Documentation](#api-documentation)
7. [Security Analysis](#security-analysis)

## Architecture Overview

### System Components

```
┌─────────────┐         ┌─────────────┐
│   Client    │◄───────►│   Server    │
│  (React)    │  HTTPS  │ (Express)   │
└─────────────┘         └─────────────┘
     │                        │
     │                        │
     ▼                        ▼
┌─────────────┐         ┌─────────────┐
│ IndexedDB   │         │  MongoDB    │
│ (Keys Only) │         │ (Metadata)  │
└─────────────┘         └─────────────┘
```

### Data Flow

1. **User Registration**: Client generates key pair, stores private key locally, sends public key to server
2. **Key Exchange**: ECDH-based protocol with digital signatures
3. **Message Encryption**: Client-side AES-GCM encryption before sending
4. **Message Storage**: Server stores only encrypted payload, IV, and metadata
5. **Message Decryption**: Client-side decryption after receiving

## Cryptographic Design

### Encryption Scheme

**Hybrid Cryptography:**
- **Asymmetric**: ECDH for key exchange (P-256 curve)
- **Symmetric**: AES-256-GCM for message encryption

### Key Management

1. **Long-term Keys**: RSA-2048 or ECC (P-256/P-384) for user identity
2. **Ephemeral Keys**: Generated per session for forward secrecy
3. **Session Keys**: Derived from shared secret using HKDF

### Encryption Process

```
Plaintext → AES-256-GCM → Ciphertext + Auth Tag
         (Fresh IV per message)
```

### Decryption Process

```
Ciphertext + Auth Tag → Verify Tag → AES-256-GCM → Plaintext
```

## Key Exchange Protocol

### Protocol Diagram

```
Alice                          Server                          Bob
  │                              │                              │
  │─── Register (PublicKey) ────►│                              │
  │                              │◄─── Register (PublicKey) ────│
  │                              │                              │
  │─── Initiate Key Exchange ───►│                              │
  │   (EphemeralPubKey + Sig)    │                              │
  │                              │─── Forward to Bob ──────────►│
  │                              │                              │
  │                              │◄─── Complete Key Exchange ───│
  │                              │   (Shared Secret)             │
  │                              │                              │
  │◄─── Key Confirmation ────────│◄─── Key Confirmation ────────│
  │                              │                              │
  │─── Encrypted Message ───────►│─── Encrypted Message ───────►│
  │                              │                              │
```

### Protocol Steps

1. **Registration Phase**
   - Alice and Bob register with their public keys
   - Server stores public keys (no private keys)

2. **Key Exchange Initiation**
   - Alice generates ephemeral key pair
   - Computes shared secret: `sharedSecret = ECDH(ephemeralPrivate, bobPublic)`
   - Signs key exchange message with long-term private key
   - Sends: `{ephemeralPublicKey, signature, timestamp}`

3. **Key Exchange Completion**
   - Bob verifies signature using Alice's public key
   - Computes shared secret: `sharedSecret = ECDH(bobPrivate, ephemeralPublic)`
   - Derives session key: `sessionKey = HKDF(sharedSecret, salt, info)`

4. **Key Confirmation**
   - Both parties exchange confirmation messages
   - Verify mutual authentication

### Security Properties

- **Authenticity**: Digital signatures prevent MITM
- **Forward Secrecy**: Ephemeral keys ensure past messages remain secure
- **Key Confirmation**: Ensures both parties have correct session key

## Threat Model

### STRIDE Analysis

| Threat | Category | Likelihood | Impact | Mitigation | Status |
|--------|-----------|-------------|--------|------------|--------|
| MITM | Spoofing | Medium | High | Digital signatures, Certificate pinning | Mitigated |
| Replay | Tampering | High | Medium | Nonces, Timestamps, Sequence numbers | Mitigated |
| Eavesdropping | Information Disclosure | High | Low | E2EE encryption, PFS | Mitigated |
| Key Compromise | Information Disclosure | Low | Critical | Key rotation, PFS | Mitigated |
| DoS | Denial of Service | Medium | Medium | Rate limiting, Validation | Partially Mitigated |
| Unauthorized Access | Elevation of Privilege | Medium | High | Authentication, Access control | Mitigated |

### Threat Details

#### T1: Man-in-the-Middle Attack

**Description**: Attacker intercepts communication and impersonates parties

**Attack Vector**:
1. Attacker positions between Alice and Bob
2. Intercepts key exchange messages
3. Replaces public keys with attacker's keys
4. Decrypts and re-encrypts messages

**Mitigation**:
- Digital signatures in key exchange
- Certificate pinning
- Public key verification
- Out-of-band key verification

**Status**: ✅ Mitigated

#### T2: Replay Attack

**Description**: Attacker captures and replays legitimate messages

**Attack Vector**:
1. Attacker captures encrypted message
2. Replays message at later time
3. Receiver processes duplicate message

**Mitigation**:
- Nonce tracking (one-time use)
- Timestamp validation (5-minute window)
- Message sequence numbers
- One-time message IDs

**Status**: ✅ Mitigated

#### T3: Eavesdropping

**Description**: Attacker intercepts encrypted messages

**Attack Vector**:
1. Attacker intercepts network traffic
2. Captures encrypted messages
3. Attempts to decrypt without keys

**Mitigation**:
- End-to-end encryption (AES-GCM)
- Perfect forward secrecy
- Session key rotation
- Strong key derivation (HKDF)

**Status**: ✅ Mitigated

#### T4: Key Compromise

**Description**: Attacker compromises encryption keys

**Attack Vector**:
1. Attacker gains access to private keys
2. Decrypts past and future messages
3. Impersonates user

**Mitigation**:
- Key rotation
- Perfect forward secrecy
- Secure key storage (IndexedDB)
- Key escrow prevention

**Status**: ✅ Mitigated

#### T5: Denial of Service

**Description**: Attacker floods server with requests

**Attack Vector**:
1. Attacker sends many requests
2. Server resources exhausted
3. Legitimate users cannot access service

**Mitigation**:
- Rate limiting
- Request validation
- Resource quotas
- Connection limits

**Status**: ⚠️ Partially Mitigated

#### T6: Unauthorized Access

**Description**: Unauthorized user accesses system

**Attack Vector**:
1. Attacker bypasses authentication
2. Accesses user data
3. Sends messages as other users

**Mitigation**:
- User authentication
- Session management
- Access control
- Audit logging

**Status**: ✅ Mitigated

## Attack Demonstrations

### MITM Attack Demo

**Location**: `src/attacks/mitm.js`

**Demonstration**:
1. Shows how MITM breaks DH without signatures
2. Demonstrates signature verification failure
3. Shows how protocol prevents MITM

**Evidence**:
- Logs showing signature verification
- Error messages for invalid signatures
- Successful prevention of MITM

### Replay Attack Demo

**Location**: `src/attacks/replay.js`

**Demonstration**:
1. Captures legitimate message
2. Attempts to replay message
3. Shows detection and rejection

**Evidence**:
- Nonce collision detection
- Sequence number validation
- Timestamp validation
- Rejection logs

## API Documentation

### Authentication Endpoints

#### POST /api/auth/register

Register a new user.

**Request**:
```json
{
  "username": "alice",
  "password": "securepass123"
}
```

**Response**:
```json
{
  "success": true,
  "username": "alice",
  "message": "User registered successfully"
}
```

#### POST /api/auth/login

Authenticate user.

**Request**:
```json
{
  "username": "alice",
  "password": "securepass123"
}
```

**Response**:
```json
{
  "success": true,
  "username": "alice",
  "lastLogin": "2025-12-03T15:00:00.000Z"
}
```

### E2EE Endpoints

#### POST /api/e2ee/register

Register user for E2EE.

**Request**:
```json
{
  "userId": "alice",
  "publicKey": [1, 2, 3, ...]
}
```

**Response**:
```json
{
  "success": true,
  "message": "User registered",
  "userId": "alice"
}
```

#### POST /api/e2ee/key-exchange/initiate

Initiate key exchange.

**Request**:
```json
{
  "senderId": "alice",
  "receiverId": "bob"
}
```

**Response**:
```json
{
  "success": true,
  "ephemeralPublicKey": [4, 212, 129, ...],
  "signature": [123, 45, 67, ...]
}
```

#### POST /api/e2ee/message/send

Send encrypted message.

**Request**:
```json
{
  "senderId": "alice",
  "receiverId": "bob",
  "message": "Hello Bob!"
}
```

**Response**:
```json
{
  "success": true,
  "encryptedMessage": {
    "encryptedPayload": [1, 2, 3, ...],
    "iv": [4, 5, 6, ...],
    "authTag": [7, 8, 9, ...],
    "sequenceNumber": 1,
    "timestamp": 1701600000000
  },
  "messageId": "alice-bob-1701600000000"
}
```

## Security Analysis

### Security Score: 91.67% (Grade A)

**Breakdown**:
- Total Threats: 6
- Mitigated: 5
- Partially Mitigated: 1
- Unmitigated: 0

### Recommendations

1. **Strengthen DoS Mitigation**:
   - Implement rate limiting per IP
   - Add CAPTCHA for suspicious activity
   - Use DDoS protection services

2. **Enhanced Key Rotation**:
   - Automatic key rotation after N messages
   - Key expiration policies
   - Key revocation mechanism

3. **Additional Security**:
   - Two-factor authentication
   - Device fingerprinting
   - Anomaly detection

## Limitations

1. **Simplified Crypto**: Some cryptographic operations use simplified implementations for educational purposes
2. **No Key Escrow**: Lost keys cannot be recovered
3. **No Message Deletion**: Messages cannot be deleted after sending
4. **Limited Scalability**: In-memory storage limits concurrent users
5. **No Offline Support**: Requires server connection

## Future Improvements

1. **Full AES-GCM Implementation**: Replace simplified crypto with full implementation
2. **Key Rotation**: Automatic key rotation mechanism
3. **Message Deletion**: End-to-end message deletion
4. **Group Messaging**: Support for group chats
5. **File Streaming**: Support for large file streaming
6. **Offline Support**: Queue messages when offline

