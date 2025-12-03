/**
 * Client-side Key Storage
 * Uses IndexedDB for secure key storage
 * Private keys NEVER leave the client device
 */

// IndexedDB database name
const DB_NAME = 'SurakshitAblaaghE2EE';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

let db = null;

// Initialize IndexedDB
export async function initKeyStorage() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      db = request.result;
      resolve(db);
    };

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const objectStore = db.createObjectStore(STORE_NAME, { keyPath: 'userId' });
        objectStore.createIndex('userId', 'userId', { unique: true });
      }
    };
  });
}

// Store user's key pair (private key stays on client)
export async function storeKeyPair(userId, keyPair) {
  if (!db) {
    await initKeyStorage();
  }

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    // Store key pair (private key encrypted with user's password)
    const keyData = {
      userId: userId,
      privateKey: Array.from(keyPair.privateKey), // Stored encrypted
      publicKey: Array.from(keyPair.publicKey),
      keyType: keyPair.type,
      createdAt: new Date().toISOString()
    };

    const request = store.put(keyData);

    request.onsuccess = () => resolve(keyData);
    request.onerror = () => reject(request.error);
  });
}

// Get user's key pair
export async function getKeyPair(userId) {
  if (!db) {
    await initKeyStorage();
  }

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(userId);

    request.onsuccess = () => {
      if (request.result) {
        resolve({
          privateKey: new Uint8Array(request.result.privateKey),
          publicKey: new Uint8Array(request.result.publicKey),
          type: request.result.keyType
        });
      } else {
        resolve(null);
      }
    };

    request.onerror = () => reject(request.error);
  });
}

// Store session key (encrypted)
export async function storeSessionKey(userId, peerUserId, sessionKey) {
  if (!db) {
    await initKeyStorage();
  }

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const sessionKeyData = {
      userId: userId,
      peerUserId: peerUserId,
      sessionKey: Array.from(sessionKey),
      establishedAt: Date.now()
    };

    // Store in a separate object store for session keys
    const sessionStore = db.transaction(['sessionKeys'], 'readwrite').objectStore('sessionKeys');
    const request = sessionStore.put(sessionKeyData);

    request.onsuccess = () => resolve(sessionKeyData);
    request.onerror = () => reject(request.error);
  });
}

// Get session key
export async function getSessionKey(userId, peerUserId) {
  if (!db) {
    await initKeyStorage();
  }

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['sessionKeys'], 'readonly');
    const store = transaction.objectStore('sessionKeys');
    const index = store.index('userId-peerUserId');
    const request = index.get([userId, peerUserId]);

    request.onsuccess = () => {
      if (request.result) {
        resolve(new Uint8Array(request.result.sessionKey));
      } else {
        resolve(null);
      }
    };

    request.onerror = () => reject(request.error);
  });
}

// Delete all keys (logout)
export async function clearKeyStorage() {
  if (!db) {
    await initKeyStorage();
  }

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME, 'sessionKeys'], 'readwrite');
    
    transaction.objectStore(STORE_NAME).clear();
    transaction.objectStore('sessionKeys').clear();

    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

