/**
 * MongoDB connection and operations
 * Stores only metadata (no plaintext, no private keys)
 */

import { MongoClient } from 'mongodb';

let client = null;
let db = null;

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'securelink_e2ee';

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
  
    return await collection
      .find({ receiverId: receiverId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray();
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
    
    return await collection.findOne({ fileId: fileId });
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

// Close database connection
export async function closeDB() {
  if (client) {
    await client.close();
    console.log('MongoDB connection closed');
  }
}

