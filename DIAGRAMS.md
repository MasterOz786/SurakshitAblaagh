# SurakshitAblaagh - Mermaid Diagrams

## 1. High-Level Architecture Diagram

```mermaid
graph TB
    subgraph Client["Client (Browser)"]
        React["React Frontend<br/>(Login, Chat)"]
        WebCrypto["Web Crypto API<br/>(Key Generation, Encryption)"]
        IndexedDB["IndexedDB<br/>(Private Keys, Session Keys)"]
        React --> WebCrypto
        React --> IndexedDB
    end
    
    subgraph Server["Server (Node.js/Express)"]
        Express["Express API<br/>(REST Endpoints)"]
        Auth["Authentication Module<br/>(Password Hashing)"]
        E2EE["E2EE API Routes<br/>(Key Exchange, Messages)"]
        Security["Security Logging<br/>(Winston)"]
        Express --> Auth
        Express --> E2EE
        Express --> Security
    end
    
    subgraph Database["Database (MongoDB)"]
        Users["Users Collection<br/>(username, passwordHash)"]
        Messages["Messages Collection<br/>(encryptedPayload, IV, metadata)"]
        Files["Files Collection<br/>(encryptedChunks)"]
        Sessions["Sessions Collection<br/>(sessionId, metadata)"]
    end
    
    Client -->|HTTPS| Server
    Server -->|Metadata Only| Database
    
    style Client fill:#e1f5ff
    style Server fill:#fff4e1
    style Database fill:#e8f5e9
    style IndexedDB fill:#ffebee
    style WebCrypto fill:#ffebee
```

## 2. Client-Side Flow Diagrams

### 2.1 User Registration Flow

```mermaid
sequenceDiagram
    participant User
    participant Login as Login Component
    participant API as API Service
    participant WebCrypto as Web Crypto API
    participant IndexedDB as IndexedDB Storage
    participant Server as Express Server
    
    User->>Login: Enter username & password
    Login->>API: registerUser(username, password)
    API->>Server: POST /api/auth/register
    Server-->>API: { success: true, username }
    API-->>Login: Registration success
    
    Login->>WebCrypto: generateECKeyPair('P-256')
    WebCrypto-->>Login: { privateKey, publicKey }
    
    Login->>IndexedDB: storeKeyPair(username, { privateKey, publicKey })
    IndexedDB-->>Login: Stored
    
    Login->>API: registerE2EEUser(username, publicKey)
    API->>Server: POST /api/e2ee/register { userId, publicKey }
    Note over Server: Store ONLY publicKey<br/>NO privateKey
    Server-->>API: { success: true }
    API-->>Login: E2EE registered
    Login-->>User: Registration complete
```

### 2.2 Key Generation and Storage Flow

```mermaid
flowchart TD
    Start([User Registration]) --> Generate[Generate ECC Key Pair<br/>generateECKeyPair P-256]
    Generate --> Export[Export Keys<br/>SPKI Public, PKCS8 Private]
    Export --> StorePrivate[Store Private Key<br/>IndexedDB: SurakshitAblaaghE2EE]
    StorePrivate --> SendPublic[Send Public Key to Server<br/>POST /api/e2ee/register]
    SendPublic --> ServerStore[Server Stores Public Key Only<br/>userSessions.set userId, publicKey]
    
    StorePrivate --> IndexedDB[(IndexedDB<br/>keys store)]
    ServerStore --> ServerMem[(Server Memory<br/>userSessions Map)]
    
    style StorePrivate fill:#ffebee
    style IndexedDB fill:#ffebee
    style ServerStore fill:#fff4e1
    style ServerMem fill:#fff4e1
```

### 2.3 Message Encryption Flow (Client-Side)

```mermaid
flowchart LR
    Input[User Input<br/>Plaintext Message] --> GetKey[Get Session Key<br/>from IndexedDB]
    GetKey --> GenIV[Generate Fresh IV<br/>crypto.getRandomValues 12 bytes]
    GenIV --> GenNonce[Generate Nonce<br/>crypto.getRandomValues 16 bytes]
    GenNonce --> IncSeq[Increment Sequence Number<br/>messageCounters Map]
    IncSeq --> Encrypt[AES-256-GCM Encrypt<br/>Web Crypto API]
    Encrypt --> CreateMsg["Create Message Structure<br/>encryptedPayload, iv, authTag, nonce, sequenceNumber"]
    CreateMsg --> Send[Send to Server<br/>POST /api/e2ee/message/send]
    Send --> Server[(Server Storage<br/>NO plaintext)]
    
    style Input fill:#e1f5ff
    style Encrypt fill:#ffebee
    style Server fill:#fff4e1
```

### 2.4 File Encryption Flow (Client-Side)

```mermaid
flowchart TD
    Select[User Selects File] --> Read[Read File as ArrayBuffer]
    Read --> Chunk[Split into 1MB Chunks]
    Chunk --> Loop{For Each Chunk}
    Loop --> GenIV[Generate Fresh IV<br/>per chunk]
    GenIV --> Encrypt[AES-256-GCM Encrypt<br/>chunk with sessionKey]
    Encrypt --> Store["Store chunkIndex, iv, encryptedData, authTag"]
    Store --> Loop
    Loop -->|All Chunks| Create["Create File Structure<br/>fileName, fileSize, encryptedChunks"]
    Create --> Upload[Upload to Server<br/>POST /api/e2ee/file/upload]
    Upload --> Server[(Server Storage<br/>encryptedChunks only)]
    
    style Select fill:#e1f5ff
    style Encrypt fill:#ffebee
    style Server fill:#fff4e1
```

## 3. Key Exchange Protocol Diagrams

### 3.1 Complete Key Exchange Protocol Flow

```mermaid
sequenceDiagram
    participant Alice
    participant AliceClient as Alice Client<br/>(Web Crypto API)
    participant Server as Express Server
    participant BobClient as Bob Client<br/>(Web Crypto API)
    participant Bob
    
    Note over Alice,Bob: Phase 1: Registration
    Alice->>AliceClient: Register with username/password
    AliceClient->>AliceClient: Generate ECC P-256 key pair
    AliceClient->>AliceClient: Store privateKey in IndexedDB
    AliceClient->>Server: POST /api/e2ee/register<br/>{ userId: "alice", publicKey }
    Note over Server: Store publicKey only<br/>NO privateKey
    
    Bob->>BobClient: Register with username/password
    BobClient->>BobClient: Generate ECC P-256 key pair
    BobClient->>BobClient: Store privateKey in IndexedDB
    BobClient->>Server: POST /api/e2ee/register<br/>{ userId: "bob", publicKey }
    
    Note over Alice,Bob: Phase 2: Key Exchange Initiation
    Alice->>AliceClient: Start session with Bob
    AliceClient->>AliceClient: Generate ephemeral ECDH key pair
    AliceClient->>AliceClient: Compute sharedSecret = ECDH(ephemeralPrivate, bobPublic)
    AliceClient->>AliceClient: Create keyExchangeMessage<br/>{ ephemeralPublicKey, timestamp, nonce }
    AliceClient->>AliceClient: Sign message with long-term privateKey
    AliceClient->>Server: POST /api/e2ee/key-exchange/initiate<br/>{ ephemeralPublicKey, signature, keyExchangeMessage }
    Server->>BobClient: Forward key exchange message
    
    Note over Alice,Bob: Phase 3: Key Exchange Completion
    BobClient->>BobClient: Verify signature with Alice's publicKey
    alt Signature Invalid
        BobClient-->>Server: Reject (MITM attack detected)
    else Signature Valid
        BobClient->>BobClient: Compute sharedSecret = ECDH(bobPrivate, ephemeralPublic)
        BobClient->>BobClient: Derive sessionKey = HKDF(sharedSecret, salt, info)
        BobClient->>Server: POST /api/e2ee/key-exchange/complete<br/>{ sessionKey, salt }
        Server->>AliceClient: Forward completion
    end
    
    Note over Alice,Bob: Phase 4: Key Confirmation
    AliceClient->>AliceClient: Generate confirmation = HMAC(sharedSecret, sessionId)
    AliceClient->>Server: POST /api/e2ee/key-exchange/confirm<br/>{ confirmation, timestamp }
    BobClient->>BobClient: Verify confirmation
    BobClient->>Server: POST /api/e2ee/key-exchange/confirm<br/>{ confirmation, timestamp }
    AliceClient->>AliceClient: Store sessionKey in IndexedDB
    BobClient->>BobClient: Store sessionKey in IndexedDB
    
    Note over Alice,Bob: Session Established
    Alice->>AliceClient: Send encrypted message
    AliceClient->>Server: POST /api/e2ee/message/send<br/>{ encryptedPayload, iv, authTag }
    Server->>BobClient: Forward encrypted message
    BobClient->>BobClient: Decrypt message
    BobClient->>Bob: Display decrypted message
```

### 3.2 Key Exchange Message Flow

```mermaid
graph LR
    subgraph Initiation["Key Exchange Initiation"]
        A1[Alice generates ephemeral key pair] --> A2[Compute sharedSecret<br/>ECDH ephemeralPrivate, bobPublic]
        A2 --> A3["Create message<br/>ephemeralPublicKey, timestamp, nonce"]
        A3 --> A4[Sign with<br/>long-term privateKey]
        A4 --> A5[Send to Server<br/>ephemeralPublicKey + signature]
    end
    
    subgraph Completion["Key Exchange Completion"]
        B1[Bob receives message] --> B2[Verify signature<br/>with Alice's publicKey]
        B2 -->|Valid| B3[Compute sharedSecret<br/>ECDH bobPrivate, ephemeralPublic]
        B2 -->|Invalid| B4[Reject - MITM attack]
        B3 --> B5[Derive sessionKey<br/>HKDF sharedSecret, salt, info]
        B5 --> B6[Send confirmation]
    end
    
    subgraph Confirmation["Key Confirmation"]
        C1[Alice generates<br/>HMAC confirmation] --> C2[Send confirmation]
        C2 --> C3[Bob verifies<br/>confirmation]
        C3 --> C4[Session established]
    end
    
    Initiation --> Completion
    Completion --> Confirmation
    
    style A4 fill:#ffebee
    style B2 fill:#ffebee
    style B4 fill:#ffcdd2
    style C4 fill:#c8e6c9
```

## 4. Encryption/Decryption Workflows

### 4.1 Message Encryption Workflow

```mermaid
flowchart TD
    Start([User Types Message]) --> GetSession[Get Session Key<br/>from IndexedDB]
    GetSession --> GenIV[Generate Fresh IV<br/>12 bytes random]
    GenIV --> GenNonce[Generate Nonce<br/>16 bytes random]
    GenNonce --> IncSeq[Increment Sequence Number<br/>messageCounters Map]
    IncSeq --> Encode[Encode Plaintext<br/>TextEncoder]
    Encode --> AESEncrypt[AES-256-GCM Encrypt<br/>Web Crypto API]
    AESEncrypt --> Extract[Extract Ciphertext<br/>and Auth Tag]
    Extract --> Create["Create Message Object<br/>type, senderId, receiverId,<br/>timestamp, nonce, sequenceNumber,<br/>iv, encryptedPayload, authTag"]
    Create --> Send["POST /api/e2ee/message/send"]
    Send --> Server[("Server Stores<br/>encryptedPayload, iv, authTag,<br/>metadata - NO plaintext")]
    
    style Start fill:#e1f5ff
    style AESEncrypt fill:#ffebee
    style Server fill:#fff4e1
```

### 4.2 Message Decryption Workflow

```mermaid
flowchart TD
    Receive[Receive Encrypted Message<br/>from Server] --> GetSession[Get Session Key<br/>from IndexedDB]
    GetSession --> VerifyTime[Verify Timestamp<br/>within 5 minutes]
    VerifyTime -->|Invalid| Reject1[Reject - Replay Attack]
    VerifyTime -->|Valid| CheckNonce[Check Nonce<br/>in nonceTracker]
    CheckNonce -->|Duplicate| Reject2[Reject - Replay Attack]
    CheckNonce -->|Unique| CheckSeq[Check Sequence Number<br/>> lastSequenceNumber]
    CheckSeq -->|Invalid| Reject3[Reject - Replay Attack]
    CheckSeq -->|Valid| AESDecrypt[AES-256-GCM Decrypt<br/>Web Crypto API]
    AESDecrypt --> VerifyTag[Verify Auth Tag<br/>automatic in AES-GCM]
    VerifyTag -->|Invalid| Reject4[Reject - Tampering Detected]
    VerifyTag -->|Valid| Update[Update Trackers<br/>nonceTracker, sequenceNumber]
    Update --> Decode[Decode Plaintext<br/>TextDecoder]
    Decode --> Display[Display Message<br/>to User]
    
    style Receive fill:#e1f5ff
    style AESDecrypt fill:#ffebee
    style Reject1 fill:#ffcdd2
    style Reject2 fill:#ffcdd2
    style Reject3 fill:#ffcdd2
    style Reject4 fill:#ffcdd2
    style Display fill:#c8e6c9
```

### 4.3 File Encryption/Decryption Workflow

```mermaid
flowchart TB
    subgraph Encryption["File Encryption (Client-Side)"]
        E1[User Selects File] --> E2[Read File<br/>ArrayBuffer]
        E2 --> E3[Split into 1MB Chunks]
        E3 --> E4[For Each Chunk]
        E4 --> E5[Generate Fresh IV<br/>12 bytes]
        E5 --> E6[AES-256-GCM Encrypt<br/>chunk]
        E6 --> E7["Store chunkIndex,<br/>iv, encryptedData, authTag"]
        E7 --> E4
        E7 --> E8["Create File Structure<br/>fileName, fileSize,<br/>encryptedChunks"]
        E8 --> E9[Upload to Server<br/>POST /api/e2ee/file/upload]
    end
    
    subgraph Decryption["File Decryption (Client-Side)"]
        D1[Request File Download] --> D2[Get Encrypted Chunks<br/>from Server]
        D2 --> D3[Get Session Key<br/>from IndexedDB]
        D3 --> D4[For Each Chunk]
        D4 --> D5[AES-256-GCM Decrypt<br/>chunk]
        D5 --> D6[Verify Auth Tag]
        D6 --> D4
        D6 --> D7[Reassemble File]
        D7 --> D8[Download to Device]
    end
    
    E9 --> Server[(Server Storage<br/>encryptedChunks only)]
    Server --> D2
    
    style E6 fill:#ffebee
    style D5 fill:#ffebee
    style Server fill:#fff4e1
```

## 5. Schema Design

### 5.1 Database Schema (MongoDB)

```mermaid
erDiagram
    USERS ||--o{ MESSAGES : sends
    USERS ||--o{ FILES : sends
    USERS ||--o{ SESSIONS : has
    
    USERS {
        string username PK
        string passwordHash
        string passwordSalt
        number passwordIterations
        date createdAt
        date lastLogin
        number failedLoginAttempts
        date lockedUntil
    }
    
    MESSAGES {
        string messageId PK
        string senderId FK
        string receiverId FK
        array encryptedPayload
        array iv
        array authTag
        number sequenceNumber
        number timestamp
        date createdAt
    }
    
    FILES {
        string fileId PK
        string senderId FK
        string receiverId FK
        string fileName
        number fileSize
        array encryptedChunks
        date createdAt
    }
    
    SESSIONS {
        string sessionId PK
        string userId FK
        string peerUserId FK
        date sessionEstablishedAt
        date lastActivity
    }
    
    Note over USERS: NO private keys stored
    Note over MESSAGES: NO plaintext stored
    Note over FILES: NO plaintext stored
```

### 5.2 IndexedDB Schema (Client-Side)

```mermaid
erDiagram
    KEY_STORE ||--o{ SESSION_STORE : user
    
    KEY_STORE {
        string userId PK
        array privateKey
        array publicKey
        string keyType
        date createdAt
    }
    
    SESSION_STORE {
        string userId PK
        string peerUserId PK
        array sessionKey
        number establishedAt
    }
    
    Note over KEY_STORE: Private keys NEVER sent to server
    Note over SESSION_STORE: Session keys in memory only
```

### 5.3 Server Memory Schema

```mermaid
erDiagram
    USER_SESSIONS {
        string userId PK
        array publicKey
        array sessionKey
        set nonceTracker
    }
    
    PENDING_KEY_EXCHANGES {
        string senderId PK
        array ephemeralPublicKey
        array sharedSecret
        string receiverId
        number timestamp
    }
    
    Note over USER_SESSIONS: In-memory Map<br/>NO private keys
    Note over PENDING_KEY_EXCHANGES: Temporary storage<br/>for key exchange
```

## 6. Deployment Description (Local)

### 6.1 Local Deployment Architecture

```mermaid
graph TB
    subgraph Developer["Developer Machine"]
        subgraph Backend["Backend Server"]
            NodeJS["Node.js Runtime<br/>v18+"]
            Express["Express Server<br/>Port 3000"]
            MongoDB["MongoDB<br/>Port 27017<br/>(Optional)"]
            NodeJS --> Express
            Express --> MongoDB
        end
        
        subgraph Frontend["Frontend Client"]
            Vite["Vite Dev Server<br/>Port 5173"]
            React["React Application"]
            Browser["Web Browser<br/>Chrome/Firefox"]
            Vite --> React
            React --> Browser
        end
        
        subgraph Storage["Client Storage"]
            IndexedDB["IndexedDB<br/>SurakshitAblaaghE2EE"]
            Browser --> IndexedDB
        end
    end
    
    Browser -->|HTTP/HTTPS<br/>localhost:3000| Express
    Express -->|Metadata Only| MongoDB
    
    style Backend fill:#fff4e1
    style Frontend fill:#e1f5ff
    style Storage fill:#ffebee
    style MongoDB fill:#e8f5e9
```

### 6.2 Deployment Flow

```mermaid
flowchart TD
    Start([Start Deployment]) --> Install1[Install Backend Dependencies<br/>npm install]
    Install1 --> Install2[Install Frontend Dependencies<br/>cd client && npm install]
    Install2 --> StartMongo{Start MongoDB?<br/>Optional}
    StartMongo -->|Yes| Mongo[MongoDB Running<br/>mongodb://localhost:27017]
    StartMongo -->|No| NoMongo[Server Continues<br/>without MongoDB]
    Mongo --> StartBackend[Start Backend Server<br/>npm start]
    NoMongo --> StartBackend
    StartBackend --> BackendRunning[Backend Running<br/>http://localhost:3000]
    BackendRunning --> StartFrontend[Start Frontend Dev Server<br/>cd client && npm run dev]
    StartFrontend --> FrontendRunning[Frontend Running<br/>http://localhost:5173]
    FrontendRunning --> OpenBrowser[Open Browser<br/>http://localhost:5173]
    OpenBrowser --> Ready([System Ready])
    
    style StartBackend fill:#fff4e1
    style StartFrontend fill:#e1f5ff
    style Ready fill:#c8e6c9
```

### 6.3 Network Architecture (Local)

```mermaid
graph LR
    subgraph Client["Client (localhost:5173)"]
        Browser["Web Browser"]
        IndexedDB["IndexedDB<br/>Private Keys"]
    end
    
    subgraph Server["Server (localhost:3000)"]
        Express["Express API"]
        Memory["In-Memory Storage<br/>userSessions Map"]
    end
    
    subgraph Database["Database (localhost:27017)"]
        MongoDB["MongoDB<br/>Metadata Only"]
    end
    
    Browser -->|HTTP Requests<br/>POST /api/auth/register<br/>POST /api/e2ee/message/send| Express
    Express -->|Store Metadata| MongoDB
    Express -->|Store Sessions| Memory
    Browser -->|Store Keys| IndexedDB
    
    Note1["Note: Private keys<br/>never leave client"]
    Note2["Note: Server stores<br/>only encrypted data"]
    
    style Browser fill:#e1f5ff
    style IndexedDB fill:#ffebee
    style Express fill:#fff4e1
    style MongoDB fill:#e8f5e9
```

### 6.4 Component Interaction Diagram

```mermaid
graph TB
    subgraph ClientComponents["Client Components"]
        Login["Login.jsx<br/>Authentication UI"]
        Chat["Chat.jsx<br/>Messaging UI"]
        WebCrypto["webCrypto.js<br/>Key Generation, Encryption"]
        KeyStorage["keyStorage.js<br/>IndexedDB Operations"]
        MessageClient["messageClient.js<br/>Message Encryption"]
        FileClient["fileClient.js<br/>File Encryption"]
        API["api.js<br/>HTTP Client"]
    end
    
    subgraph ServerComponents["Server Components"]
        App["app.js<br/>Express Server"]
        AuthRoutes["auth/routes.js<br/>Authentication"]
        E2EERoutes["e2ee/api.js<br/>E2EE Operations"]
        AuthLogic["auth/auth.js<br/>Password Hashing"]
        MongoDB["db/mongodb.js<br/>Database Operations"]
        Security["security/logging.js<br/>Event Logging"]
    end
    
    Login --> API
    Chat --> API
    Login --> WebCrypto
    Login --> KeyStorage
    Chat --> MessageClient
    Chat --> FileClient
    MessageClient --> WebCrypto
    FileClient --> WebCrypto
    
    API --> App
    App --> AuthRoutes
    App --> E2EERoutes
    AuthRoutes --> AuthLogic
    E2EERoutes --> MongoDB
    AuthRoutes --> Security
    E2EERoutes --> Security
    
    style ClientComponents fill:#e1f5ff
    style ServerComponents fill:#fff4e1
```

---

## Diagram Usage

These Mermaid diagrams can be:
1. **Rendered in Markdown viewers** (GitHub, GitLab, VS Code with Mermaid extension)
2. **Exported to images** using Mermaid CLI or online tools
3. **Included in PDF reports** by converting to images
4. **Embedded in documentation** websites

All diagrams are based on the actual codebase implementation.

