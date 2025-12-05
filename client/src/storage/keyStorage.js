/**
 * Client-side Key Storage
 * Uses IndexedDB for secure key storage
 * Private keys NEVER leave the client device
 */

// IndexedDB database name
const DB_NAME = 'SurakshitAblaaghE2EE';
const DB_VERSION = 2; // Incremented to trigger upgrade and create sessionKeys store
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
      const oldVersion = event.oldVersion;
      
      // Create keys store if it doesn't exist
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const objectStore = db.createObjectStore(STORE_NAME, { keyPath: 'userId' });
        objectStore.createIndex('userId', 'userId', { unique: true });
      }
      
      // Create sessionKeys store if upgrading from version 1 or if it doesn't exist
      if (oldVersion < 2 || !db.objectStoreNames.contains('sessionKeys')) {
        if (!db.objectStoreNames.contains('sessionKeys')) {
          const sessionStore = db.createObjectStore('sessionKeys', { keyPath: ['userId', 'peerUserId'] });
          sessionStore.createIndex('userId-peerUserId', ['userId', 'peerUserId'], { unique: true });
        }
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
    // Ensure sessionKeys store exists
    if (!db.objectStoreNames.contains('sessionKeys')) {
      reject(new Error('sessionKeys object store not found. Please refresh the page to upgrade the database.'));
      return;
    }

    const transaction = db.transaction(['sessionKeys'], 'readwrite');
    const sessionStore = transaction.objectStore('sessionKeys');

    const sessionKeyData = {
      userId: userId,
      peerUserId: peerUserId,
      sessionKey: Array.from(sessionKey),
      establishedAt: Date.now()
    };

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

// Get all active sessions for a user
export async function getAllSessions(userId) {
  if (!db) {
    await initKeyStorage();
  }

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['sessionKeys'], 'readonly');
    const store = transaction.objectStore('sessionKeys');
    const request = store.openCursor();

    const sessions = [];

    request.onsuccess = (event) => {
      const cursor = event.target.result;
      if (cursor) {
        const value = cursor.value;
        if (value.userId === userId) {
          sessions.push({
            peerUserId: value.peerUserId,
            establishedAt: value.establishedAt,
            sessionKey: new Uint8Array(value.sessionKey)
          });
        }
        cursor.continue();
      } else {
        resolve(sessions);
      }
    };

    request.onerror = () => reject(request.error);
  });
}

// Delete a specific session
export async function deleteSession(userId, peerUserId) {
  if (!db) {
    await initKeyStorage();
  }

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['sessionKeys'], 'readwrite');
    const store = transaction.objectStore('sessionKeys');
    
    // Use the key path [userId, peerUserId] to delete
    // The keyPath is ['userId', 'peerUserId'] so we delete using that composite key
    const request = store.delete([userId, peerUserId]);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

// Delete all keys (logout)
export async function clearKeyStorage() {
  if (!db) {
    await initKeyStorage();
  }

  return new Promise((resolve, reject) => {
    try {
      const stores = [STORE_NAME];
      // Add sessionKeys store if it exists
      if (db.objectStoreNames.contains('sessionKeys')) {
        stores.push('sessionKeys');
      }
      
      const transaction = db.transaction(stores, 'readwrite');
      
      // Clear all stores
      stores.forEach(storeName => {
        transaction.objectStore(storeName).clear();
      });

      transaction.oncomplete = () => {
        console.log('Key storage cleared successfully');
        resolve();
      };
      transaction.onerror = () => {
        console.error('Error clearing key storage:', transaction.error);
        reject(transaction.error);
      };
    } catch (error) {
      console.error('Error in clearKeyStorage:', error);
      // Even if there's an error, resolve to allow logout
      resolve();
    }
  });
}

