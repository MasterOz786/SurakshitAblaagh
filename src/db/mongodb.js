/**
 * MongoDB connection and operations
 * Stores only metadata (no plaintext, no private keys)
 */

import { MongoClient } from 'mongodb';
import { logMetadataAccess } from '../security/logging.js';

let client = null;
let db = null;

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'surakshitablaagh_e2ee';

// Connect to MongoDB
export async function connectDB() {
  try {
    client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db(DB_NAME);
    console.log('✓ Connected to MongoDB');
    return db;
  } catch (error) {
    console.warn('⚠️  MongoDB connection failed (continuing without DB):', error.message);
    console.warn('⚠️  Server will continue but metadata storage will be disabled');
    // Don't throw - allow server to continue without MongoDB for testing
    return null;
  }
}

// Get database instance
export function getDB() {
  // Return null if not connected (for testing without MongoDB)
  return db;
}

// Store encrypted message metadata
export async function storeMessageMetadata(messageMetadata) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('messages');
  
  // Store only metadata - NO plaintext, NO decryption keys
  const doc = {
    messageId: messageMetadata.messageId,
    senderId: messageMetadata.senderId,
    receiverId: messageMetadata.receiverId,
    timestamp: messageMetadata.timestamp,
    sequenceNumber: messageMetadata.sequenceNumber,
    // Encrypted payload stored (server cannot decrypt)
    encryptedPayload: messageMetadata.encryptedPayload,
    iv: messageMetadata.iv,
    authTag: messageMetadata.authTag,
    nonce: messageMetadata.nonce || null, // Store nonce for replay protection
    createdAt: new Date()
  };
  
    await collection.insertOne(doc);
    return doc;
  } catch (error) {
    console.warn('Failed to store message metadata:', error.message);
    return null;
  }
}

// Get message metadata
export async function getMessageMetadata(receiverId, limit = 50) {
  try {
    const db = getDB();
    if (!db) return []; // MongoDB not available
    const collection = db.collection('messages');
  
    const results = await collection
      .find({ receiverId: receiverId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray();
    
    // Log metadata access
    logMetadataAccess(receiverId, 'message_query', `receiver:${receiverId}`);
    
    return results;
  } catch (error) {
    console.warn('Failed to get message metadata:', error.message);
    return [];
  }
}

// Store encrypted file metadata
export async function storeFileMetadata(fileMetadata) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('files');
  
  const doc = {
    fileId: fileMetadata.fileId,
    senderId: fileMetadata.senderId,
    receiverId: fileMetadata.receiverId,
    fileName: fileMetadata.fileName,
    fileSize: fileMetadata.fileSize,
    encryptedChunks: fileMetadata.encryptedChunks,
    createdAt: new Date()
  };
  
    await collection.insertOne(doc);
    return doc;
  } catch (error) {
    console.warn('Failed to store file metadata:', error.message);
    return null;
  }
}

// Get file metadata
export async function getFileMetadata(fileId) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('files');
    
    const result = await collection.findOne({ fileId: fileId });
    
    // Log metadata access
    if (result) {
      logMetadataAccess(result.receiverId || 'unknown', 'file_query', fileId);
    }
    
    return result;
  } catch (error) {
    console.warn('Failed to get file metadata:', error.message);
    return null;
  }
}

// Store user session metadata (NO private keys)
export async function storeSessionMetadata(sessionMetadata) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('sessions');
  
  const doc = {
    sessionId: sessionMetadata.sessionId,
    userId: sessionMetadata.userId,
    peerUserId: sessionMetadata.peerUserId,
    sessionEstablishedAt: sessionMetadata.sessionEstablishedAt,
    lastActivity: new Date()
    // NO private keys stored
  };
  
    await collection.insertOne(doc);
    return doc;
  } catch (error) {
    console.warn('Failed to store session metadata:', error.message);
    return null;
  }
}

// User Management Functions
// Store user in MongoDB
export async function storeUser(userData) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('users');
    
    const doc = {
      username: userData.username,
      passwordHash: userData.passwordHash,
      passwordSalt: userData.passwordSalt,
      passwordIterations: userData.passwordIterations,
      createdAt: userData.createdAt || new Date(),
      lastLogin: userData.lastLogin || null,
      failedLoginAttempts: userData.failedLoginAttempts || 0,
      lockedUntil: userData.lockedUntil || null,
      oauthProvider: userData.oauthProvider || null,
      oauthId: userData.oauthId || null,
      email: userData.email || null,
      name: userData.name || null,
      picture: userData.picture || null,
      updatedAt: new Date()
    };
    
    await collection.insertOne(doc);
    return doc;
  } catch (error) {
    console.warn('Failed to store user:', error.message);
    return null;
  }
}

// Get user from MongoDB
export async function getUserFromDB(username) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('users');
    
    return await collection.findOne({ username: username });
  } catch (error) {
    console.warn('Failed to get user:', error.message);
    return null;
  }
}

// Update user in MongoDB
export async function updateUser(username, updateData) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('users');
    
    const result = await collection.updateOne(
      { username: username },
      { 
        $set: {
          ...updateData,
          updatedAt: new Date()
        }
      }
    );
    
    return result.modifiedCount > 0;
  } catch (error) {
    console.warn('Failed to update user:', error.message);
    return false;
  }
}

// Check if user exists in MongoDB
export async function userExistsInDB(username) {
  try {
    const db = getDB();
    if (!db) return false; // MongoDB not available
    const collection = db.collection('users');
    
    const count = await collection.countDocuments({ username: username });
    return count > 0;
  } catch (error) {
    console.warn('Failed to check user existence:', error.message);
    return false;
  }
}

// Get all users from MongoDB (for recipient selection)
export async function getAllUsers(excludeUsername = null) {
  try {
    const db = getDB();
    if (!db) return []; // MongoDB not available
    
    const collection = db.collection('users');
    const query = excludeUsername ? { username: { $ne: excludeUsername } } : {};
    
    const users = await collection.find(query, {
      projection: { 
        username: 1, 
        email: 1, 
        name: 1, 
        createdAt: 1,
        lastLogin: 1,
        _id: 0 
      }
    }).toArray();
    
    return users.map(user => ({
      username: user.username,
      email: user.email || null,
      name: user.name || null,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin || null
    }));
  } catch (error) {
    console.warn('Failed to get all users:', error.message);
    return [];
  }
}

// E2EE User Sessions Functions
// Store E2EE user session
export async function storeE2EEUserSession(userId, sessionData) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('e2ee_users');
    
    const doc = {
      userId: userId,
      publicKey: Array.from(sessionData.publicKey || []),
      sessionKey: sessionData.sessionKey ? Array.from(sessionData.sessionKey) : null,
      nonceTracker: sessionData.nonceTracker ? Array.from(sessionData.nonceTracker) : [],
      lastActivity: new Date(),
      updatedAt: new Date()
    };
    
    await collection.updateOne(
      { userId: userId },
      { $set: doc },
      { upsert: true }
    );
    
    return doc;
  } catch (error) {
    console.warn('Failed to store E2EE user session:', error.message);
    return null;
  }
}

// Get E2EE user session
export async function getE2EEUserSession(userId) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('e2ee_users');
    
    const result = await collection.findOne({ userId: userId });
    
    if (result) {
      return {
        publicKey: new Uint8Array(result.publicKey || []),
        sessionKey: result.sessionKey ? new Uint8Array(result.sessionKey) : null,
        nonceTracker: new Set(result.nonceTracker || [])
      };
    }
    
    return null;
  } catch (error) {
    console.warn('Failed to get E2EE user session:', error.message);
    return null;
  }
}

// Update E2EE user session
export async function updateE2EEUserSession(userId, updateData) {
  try {
    const db = getDB();
    if (!db) return false; // MongoDB not available
    const collection = db.collection('e2ee_users');
    
    const updateDoc = {
      lastActivity: new Date(),
      updatedAt: new Date()
    };
    
    if (updateData.sessionKey) {
      updateDoc.sessionKey = Array.from(updateData.sessionKey);
    }
    
    if (updateData.nonceTracker) {
      updateDoc.nonceTracker = Array.from(updateData.nonceTracker);
    }
    
    const result = await collection.updateOne(
      { userId: userId },
      { $set: updateDoc }
    );
    
    return result.modifiedCount > 0 || result.upsertedCount > 0;
  } catch (error) {
    console.warn('Failed to update E2EE user session:', error.message);
    return false;
  }
}

// Store pending key exchange
export async function storePendingKeyExchange(userId, exchangeData) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('pending_key_exchanges');
    
    // Use senderId as part of the key to allow multiple pending exchanges
    const key = exchangeData.senderId ? `${userId}-${exchangeData.senderId}` : userId;
    
    const doc = {
      userId: userId,
      senderId: exchangeData.senderId || null,
      ephemeralPublicKey: Array.from(exchangeData.ephemeralPublicKey || []),
      keyExchangeMessage: exchangeData.keyExchangeMessage || null,
      signature: exchangeData.signature ? Array.from(exchangeData.signature) : null,
      timestamp: exchangeData.timestamp || Date.now(),
      createdAt: new Date()
    };
    
    await collection.updateOne(
      { userId: userId, senderId: exchangeData.senderId || null },
      { $set: doc },
      { upsert: true }
    );
    
    // Clean up old pending exchanges (older than 1 hour)
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    await collection.deleteMany({ timestamp: { $lt: oneHourAgo } });
    
    return doc;
  } catch (error) {
    console.warn('Failed to store pending key exchange:', error.message);
    return null;
  }
}

// Get pending key exchange for a specific sender
export async function getPendingKeyExchange(userId, senderId = null) {
  try {
    const db = getDB();
    if (!db) return null; // MongoDB not available
    const collection = db.collection('pending_key_exchanges');
    const query = senderId 
      ? { userId: userId, senderId: senderId }
      : { userId: userId };
    const doc = await collection.findOne(query, { sort: { timestamp: -1 } }); // Get most recent
    return doc;
  } catch (error) {
    console.warn('Failed to get pending key exchange:', error.message);
    return null;
  }
}

// Delete pending key exchange
export async function deletePendingKeyExchange(userId, senderId = null) {
  try {
    const db = getDB();
    if (!db) return false; // MongoDB not available
    const collection = db.collection('pending_key_exchanges');
    const query = senderId 
      ? { userId: userId, senderId: senderId }
      : { userId: userId };
    const result = await collection.deleteOne(query);
    return result.deletedCount > 0;
  } catch (error) {
    console.warn('Failed to delete pending key exchange:', error.message);
    return false;
  }
}

// Close database connection
export async function closeDB() {
  if (client) {
    await client.close();
    console.log('MongoDB connection closed');
  }
}

