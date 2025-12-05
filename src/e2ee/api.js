/**
 * Express API routes for E2EE messaging system
 */

import express from 'express';
import { decryptMessage, verifyMessage } from './message.js';
import { encryptFile, decryptFile } from './fileHandler.js';
import { 
  initiateKeyExchange, 
  completeKeyExchange, 
  deriveSessionKey,
  generateKeyConfirmation,
  verifyKeyConfirmation,
  generateECDHKeyPair
} from './keyExchange.js';
import { generateSalt } from './crypto.js';
import { storeMessageMetadata, storeFileMetadata, storeSessionMetadata } from '../db/mongodb.js';
import { 
  logSecurityEvent, 
  SecurityEventType,
  logDecryptionFailure,
  logInvalidSignature,
  logMetadataAccess
} from '../security/logging.js';
import {
  storeE2EEUserSession,
  getE2EEUserSession,
  updateE2EEUserSession,
  storePendingKeyExchange,
  getPendingKeyExchange,
  deletePendingKeyExchange,
  getDB
} from '../db/mongodb.js';

// In-memory fallback cache (MongoDB is source of truth)
const userSessionsCache = new Map(); // userId -> { sessionKey, publicKey, nonceTracker }
const pendingKeyExchangesCache = new Map(); // userId -> { ephemeralPublicKey, timestamp }

export function createE2EERoutes() {
  const router = express.Router();

  // Register user and initiate key exchange
  router.post('/register', async (req, res) => {
    const { userId, publicKey } = req.body;
    
    if (!userId || !publicKey) {
      return res.status(400).json({ error: 'userId and publicKey required' });
    }

    // Store user's public key in MongoDB
    const db = getDB();
    const sessionData = {
      publicKey: new Uint8Array(publicKey),
      sessionKey: null,
      nonceTracker: new Set()
    };
    
    if (db) {
      await storeE2EEUserSession(userId, sessionData);
    } else {
      // Fallback to in-memory
      userSessionsCache.set(userId, sessionData);
    }

    res.json({ 
      success: true, 
      message: 'User registered',
      userId: userId
    });
  });

  // Get user's public key (for key exchange)
  router.get('/user/:userId', async (req, res) => {
    const { userId } = req.params;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId required' });
    }

    // Get user from MongoDB or cache
    const db = getDB();
    let user = null;
    
    if (db) {
      user = await getE2EEUserSession(userId);
      if (user) {
        userSessionsCache.set(userId, user);
      }
    } else {
      user = userSessionsCache.get(userId);
    }
    
    if (!user || !user.publicKey) {
      return res.status(404).json({ error: 'User not found or has no public key' });
    }

    res.json({
      success: true,
      userId: userId,
      publicKey: Array.from(user.publicKey)
    });
  });

  // Initiate key exchange (User A sends their ephemeral public key to User B)
  router.post('/key-exchange/initiate', async (req, res) => {
    const { senderId, receiverId, ephemeralPublicKey, keyExchangeMessage, signature } = req.body;

    if (!senderId || !receiverId || !ephemeralPublicKey || !keyExchangeMessage) {
      return res.status(400).json({ error: 'senderId, receiverId, ephemeralPublicKey, and keyExchangeMessage required' });
    }

    // Get receiver from MongoDB or cache
    const db = getDB();
    let receiver = null;
    
    if (db) {
      receiver = await getE2EEUserSession(receiverId);
      if (receiver) {
        userSessionsCache.set(receiverId, receiver);
      }
    } else {
      receiver = userSessionsCache.get(receiverId);
    }
    
    if (!receiver) {
      return res.status(404).json({ error: 'Receiver not found' });
    }

    // Store the key exchange initiation for the receiver to respond
    // Key: receiverId (who will respond), Value: senderId's ephemeral public key
    const exchangeData = {
      senderId: senderId,
      ephemeralPublicKey: Array.from(ephemeralPublicKey),
      keyExchangeMessage: keyExchangeMessage,
      signature: signature ? Array.from(signature) : null,
      timestamp: Date.now()
    };
    
    if (db) {
      await storePendingKeyExchange(receiverId, exchangeData);
    } else {
      pendingKeyExchangesCache.set(receiverId, exchangeData);
    }

    res.json({
      success: true,
      message: 'Key exchange initiated. Waiting for receiver to respond.'
    });
  });

  // Respond to key exchange (User B sends their ephemeral public key to User A)
  // senderId = User B (the responder), receiverId = User A (the initiator)
  router.post('/key-exchange/respond', async (req, res) => {
    const { senderId, receiverId, ephemeralPublicKey, keyExchangeMessage, signature } = req.body;

    if (!senderId || !receiverId || !ephemeralPublicKey || !keyExchangeMessage) {
      return res.status(400).json({ error: 'senderId, receiverId, ephemeralPublicKey, and keyExchangeMessage required' });
    }

    // Get initiator (User A) from MongoDB or cache
    const db = getDB();
    let initiator = null;
    
    if (db) {
      initiator = await getE2EEUserSession(receiverId);
      if (initiator) {
        userSessionsCache.set(receiverId, initiator);
      }
    } else {
      initiator = userSessionsCache.get(receiverId);
    }
    
    if (!initiator) {
      return res.status(404).json({ error: 'Initiator not found' });
    }

    // Get the pending key exchange from User A (initiator)
    // When User A initiated, it was stored with userId = User B (senderId), senderId = User A (receiverId)
    // So we look for: userId = senderId (User B, the responder), senderId = receiverId (User A, the initiator)
    let pendingExchange = null;
    if (db) {
      pendingExchange = await getPendingKeyExchange(senderId, receiverId);
    } else {
      const cached = pendingKeyExchangesCache.get(senderId);
      if (cached && cached.senderId === receiverId) {
        pendingExchange = cached;
      }
    }

    if (!pendingExchange) {
      return res.status(404).json({ error: 'No pending key exchange found. User A must initiate first.' });
    }

    // Store User B's ephemeral public key for User A to complete
    // Store with userId = receiverId (User A), senderId = senderId (User B)
    const responseData = {
      senderId: senderId, // User B (the responder)
      ephemeralPublicKey: Array.from(ephemeralPublicKey),
      keyExchangeMessage: keyExchangeMessage,
      signature: signature ? Array.from(signature) : null,
      timestamp: Date.now()
    };

    if (db) {
      // Store response for User A to retrieve (overwrites the initiation with response)
      await storePendingKeyExchange(receiverId, responseData);
    } else {
      // Store in cache with key = receiverId (User A)
      pendingKeyExchangesCache.set(receiverId, responseData);
    }

    res.json({
      success: true,
      message: 'Key exchange response sent. Waiting for initiator to complete.',
      initiatorEphemeralPublicKey: pendingExchange.ephemeralPublicKey,
      initiatorKeyExchangeMessage: pendingExchange.keyExchangeMessage,
      initiatorSignature: pendingExchange.signature
    });
  });

  // Get pending key exchange response (for initiator to complete)
  router.get('/key-exchange/pending/:userId/:senderId', async (req, res) => {
    const { userId, senderId } = req.params;

    if (!userId || !senderId) {
      return res.status(400).json({ error: 'userId and senderId required' });
    }

    const db = getDB();
    let pendingExchange = null;
    
    if (db) {
      pendingExchange = await getPendingKeyExchange(userId, senderId);
    } else {
      const cached = pendingKeyExchangesCache.get(userId);
      if (cached && cached.senderId === senderId) {
        pendingExchange = cached;
      }
    }

    if (!pendingExchange) {
      return res.json({
        success: false,
        message: 'No pending key exchange found'
      });
    }

    res.json({
      success: true,
      ephemeralPublicKey: pendingExchange.ephemeralPublicKey,
      keyExchangeMessage: pendingExchange.keyExchangeMessage,
      signature: pendingExchange.signature
    });
  });

  // Complete key exchange (accepts client-side session key)
  router.post('/key-exchange/complete', async (req, res) => {
    const { senderId, receiverId, sessionKey, salt } = req.body;

    if (!senderId || !receiverId || !sessionKey) {
      return res.status(400).json({ error: 'Missing required fields: senderId, receiverId, and sessionKey' });
    }

    // Get sender and receiver from MongoDB or cache
    const db = getDB();
    let sender = null;
    let receiver = null;
    
    if (db) {
      sender = await getE2EEUserSession(senderId);
      receiver = await getE2EEUserSession(receiverId);
      if (sender) {
        userSessionsCache.set(senderId, sender);
      }
      if (receiver) {
        userSessionsCache.set(receiverId, receiver);
      }
    } else {
      sender = userSessionsCache.get(senderId);
      receiver = userSessionsCache.get(receiverId);
    }
    
    if (!sender) {
      return res.status(404).json({ error: 'Sender not found' });
    }
    
    if (!receiver) {
      return res.status(404).json({ error: 'Receiver not found' });
    }

    try {
      // Store session key for both users (client already derived it)
      const sessionKeyArray = new Uint8Array(sessionKey);
      
      // Check if receiver already has a session key (from their own key exchange)
      // If they do, and it's different, we have a mismatch - use the first one established
      const existingReceiverKey = receiver.sessionKey;
      const existingSenderKey = sender.sessionKey;
      
      let finalSessionKey = sessionKeyArray;
      
      // If receiver already has a session key, check if it matches
      if (existingReceiverKey && existingReceiverKey.length > 0) {
        const receiverKeyArray = existingReceiverKey instanceof Uint8Array 
          ? existingReceiverKey 
          : new Uint8Array(existingReceiverKey);
        
        // Compare keys byte by byte
        const keysMatch = receiverKeyArray.length === sessionKeyArray.length &&
          receiverKeyArray.every((byte, i) => byte === sessionKeyArray[i]);
        
        if (!keysMatch) {
          // Keys don't match - use the existing one (first established wins)
          console.warn(`Session key mismatch detected. Using existing session key for ${receiverId}`);
          finalSessionKey = receiverKeyArray;
        }
      }
      
      // If sender already has a session key, check if it matches
      if (existingSenderKey && existingSenderKey.length > 0) {
        const senderKeyArray = existingSenderKey instanceof Uint8Array 
          ? existingSenderKey 
          : new Uint8Array(existingSenderKey);
        
        // Compare keys byte by byte
        const keysMatch = senderKeyArray.length === finalSessionKey.length &&
          senderKeyArray.every((byte, i) => byte === finalSessionKey[i]);
        
        if (!keysMatch) {
          // Keys don't match - use the existing one (first established wins)
          console.warn(`Session key mismatch detected. Using existing session key for ${senderId}`);
          finalSessionKey = senderKeyArray;
        }
      }
      
      const senderSession = {
        sessionKey: finalSessionKey,
        nonceTracker: sender.nonceTracker || new Set()
      };
      
      const receiverSession = {
        sessionKey: finalSessionKey,
        nonceTracker: receiver.nonceTracker || new Set()
      };
      
      if (db) {
        await updateE2EEUserSession(senderId, senderSession);
        await updateE2EEUserSession(receiverId, receiverSession);
      } else {
        if (!userSessionsCache.has(senderId)) {
          userSessionsCache.set(senderId, { nonceTracker: new Set() });
        }
        if (!userSessionsCache.has(receiverId)) {
          userSessionsCache.set(receiverId, { nonceTracker: new Set() });
        }
        userSessionsCache.get(senderId).sessionKey = finalSessionKey;
        userSessionsCache.get(receiverId).sessionKey = finalSessionKey;
      }

      // Store session metadata in MongoDB
      const sessionId = `${senderId}-${receiverId}-${Date.now()}`;
      storeSessionMetadata({
        sessionId: sessionId,
        userId: senderId,
        peerUserId: receiverId,
        sessionEstablishedAt: new Date()
      });

      logSecurityEvent(SecurityEventType.KEY_EXCHANGE, {
        senderId,
        receiverId,
        success: true
      });

      res.json({
        success: true,
        message: 'Key exchange completed',
        sessionEstablished: true
      });
    } catch (error) {
      // Log key exchange failure
      logSecurityEvent(SecurityEventType.KEY_EXCHANGE_FAILED, {
        senderId,
        receiverId,
        reason: error.message,
        error: error.message
      });

      res.status(400).json({
        error: 'Key exchange failed',
        details: error.message
      });
    }
  });

  // Verify key confirmation (final step)
  router.post('/key-exchange/confirm', async (req, res) => {
    const { senderId, receiverId, sessionId, confirmation, timestamp } = req.body;

    if (!senderId || !receiverId || !sessionId || !confirmation) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Get user from MongoDB or cache
    const db = getDB();
    let user = null;
    
    if (db) {
      user = await getE2EEUserSession(receiverId);
      if (user) {
        userSessionsCache.set(receiverId, user);
      }
    } else {
      user = userSessionsCache.get(receiverId);
    }
    
    if (!user || !user.sessionKey) {
      return res.status(400).json({ error: 'Session not established' });
    }

    try {
      // Key confirmation is a client-to-client verification
      // Server just acknowledges receipt - actual verification happens client-side
      // The confirmation proves both parties have the same shared secret
      
      // For now, we just log and acknowledge
      // In a production system, you might want to store confirmation status
      
      res.json({
        success: true,
        message: 'Key confirmation received'
      });
    } catch (error) {
      res.status(400).json({
        error: 'Key confirmation failed',
        details: error.message
      });
    }
  });

  // Send encrypted message (message is already encrypted client-side)
  router.post('/message/send', async (req, res) => {
    // Accept the entire encrypted message object from client
    // Client encrypts on their side - server just stores metadata
    const encryptedMessage = req.body;

    if (!encryptedMessage || !encryptedMessage.senderId || !encryptedMessage.receiverId) {
      return res.status(400).json({ error: 'Missing required fields: encryptedMessage with senderId and receiverId' });
    }

    const { senderId, receiverId } = encryptedMessage;

    // Get sender from MongoDB or cache (just to verify session exists)
    const db = getDB();
    let sender = null;
    
    if (db) {
      sender = await getE2EEUserSession(senderId);
      if (sender) {
        userSessionsCache.set(senderId, sender);
      }
    } else {
      sender = userSessionsCache.get(senderId);
    }
    
    if (!sender || !sender.sessionKey) {
      return res.status(400).json({ error: 'Session not established' });
    }

    // Message is already encrypted client-side - just store metadata
    // NO server-side encryption - this is E2EE!
    const messageId = `${senderId}-${receiverId}-${Date.now()}`;
    await storeMessageMetadata({
      messageId: messageId,
      senderId: senderId,
      receiverId: receiverId,
      timestamp: encryptedMessage.timestamp,
      sequenceNumber: encryptedMessage.sequenceNumber,
      encryptedPayload: encryptedMessage.encryptedPayload,
      iv: encryptedMessage.iv,
      authTag: encryptedMessage.authTag,
      nonce: encryptedMessage.nonce || null // Store nonce for replay protection
    });
    
    // Log metadata access (server storing metadata)
    logMetadataAccess('server', 'message_store', messageId);

    logSecurityEvent(SecurityEventType.MESSAGE_SENT, {
      senderId,
      receiverId,
      messageId: messageId
    });

    res.json({
      success: true,
      messageId: messageId
    });
  });

  // Get pending messages for a user
  router.get('/messages/:receiverId', async (req, res) => {
    const { receiverId } = req.params;

    if (!receiverId) {
      return res.status(400).json({ error: 'receiverId required' });
    }

    // Get messages from MongoDB
    const db = getDB();
    if (!db) {
      return res.json({
        success: true,
        messages: [],
        count: 0
      });
    }

    try {
      const collection = db.collection('messages');
      // Get messages where receiverId matches
      const messages = await collection.find({
        receiverId: receiverId
      }).sort({ timestamp: 1 }).toArray();

      // Log metadata access
      logMetadataAccess(receiverId, 'message_query', `receiver:${receiverId}`);

      res.json({
        success: true,
        messages: messages,
        count: messages.length
      });
    } catch (error) {
      console.error('Failed to get messages:', error);
      res.status(500).json({ error: 'Failed to get messages' });
    }
  });

  // Receive and decrypt message
  router.post('/message/receive', async (req, res) => {
    const { receiverId, encryptedMessage } = req.body;

    if (!receiverId || !encryptedMessage) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Get receiver from MongoDB or cache
    const db = getDB();
    let receiver = null;
    
    if (db) {
      receiver = await getE2EEUserSession(receiverId);
      if (receiver) {
        userSessionsCache.set(receiverId, receiver);
      }
    } else {
      receiver = userSessionsCache.get(receiverId);
    }
    
    if (!receiver || !receiver.sessionKey) {
      return res.status(400).json({ error: 'Session not established' });
    }

    try {
      // Verify message (replay protection)
      verifyMessage(encryptedMessage, receiver.nonceTracker);

      // Decrypt message
      const sessionKey = new Uint8Array(receiver.sessionKey);
      const decrypted = decryptMessage(encryptedMessage, sessionKey);

      // Update nonce tracker in MongoDB
      if (db) {
        await updateE2EEUserSession(receiverId, {
          nonceTracker: receiver.nonceTracker
        });
      } else {
        userSessionsCache.set(receiverId, receiver);
      }

      logSecurityEvent(SecurityEventType.MESSAGE_RECEIVED, {
        senderId: decrypted.senderId,
        receiverId: receiverId,
        messageId: encryptedMessage.messageId
      });

      res.json({
        success: true,
        message: decrypted
      });
    } catch (error) {
      // Check if it's a replay attack or decryption failure
      if (error.message.includes('replay') || error.message.includes('nonce') || error.message.includes('sequence')) {
        logSecurityEvent(SecurityEventType.REPLAY_DETECTED, {
          receiverId: receiverId,
          senderId: encryptedMessage.senderId,
          error: error.message,
          timestamp: Date.now()
        });
      } else if (error.message.includes('decrypt') || error.message.includes('authentication') || error.message.includes('tag')) {
        // Log failed decryption
        logDecryptionFailure(receiverId, encryptedMessage.senderId, error);
      } else {
        // Generic error - could be decryption failure
        logDecryptionFailure(receiverId, encryptedMessage.senderId, error);
      }

      res.status(400).json({
        error: 'Message verification or decryption failed',
        details: error.message
      });
    }
  });

  // Upload encrypted file
  router.post('/file/upload', async (req, res) => {
    const { senderId, receiverId, fileName, fileData } = req.body;

    if (!senderId || !receiverId || !fileName || !fileData) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Get sender from MongoDB or cache
    const db = getDB();
    let sender = null;
    
    if (db) {
      sender = await getE2EEUserSession(senderId);
      if (sender) {
        userSessionsCache.set(senderId, sender);
      }
    } else {
      sender = userSessionsCache.get(senderId);
    }
    
    if (!sender || !sender.sessionKey) {
      return res.status(400).json({ error: 'Session not established' });
    }

    // Encrypt file
    const sessionKey = new Uint8Array(sender.sessionKey);
    const fileBuffer = Buffer.from(fileData, 'base64');
    const encrypted = encryptFile(fileBuffer, sessionKey, fileName);

    res.json({
      success: true,
      encryptedFile: encrypted
    });
  });

  // Download and decrypt file
  router.post('/file/download', async (req, res) => {
    const { receiverId, encryptedFile } = req.body;

    if (!receiverId || !encryptedFile) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Get receiver from MongoDB or cache
    const db = getDB();
    let receiver = null;
    
    if (db) {
      receiver = await getE2EEUserSession(receiverId);
      if (receiver) {
        userSessionsCache.set(receiverId, receiver);
      }
    } else {
      receiver = userSessionsCache.get(receiverId);
    }
    
    if (!receiver || !receiver.sessionKey) {
      return res.status(400).json({ error: 'Session not established' });
    }

    try {
      // Decrypt file
      const sessionKey = new Uint8Array(receiver.sessionKey);
      const decrypted = decryptFile(encryptedFile, sessionKey);

      res.json({
        success: true,
        fileName: decrypted.fileName,
        fileData: decrypted.data.toString('base64'),
        size: decrypted.size
      });
    } catch (error) {
      res.status(400).json({
        error: 'File decryption failed',
        details: error.message
      });
    }
  });

  return router;
}

