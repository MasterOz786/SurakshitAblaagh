/**
 * Express API routes for E2EE messaging system
 */

import express from 'express';
import { encryptMessage, decryptMessage, verifyMessage } from './message.js';
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

// In-memory storage (in production, use database)
const userSessions = new Map(); // userId -> { sessionKey, publicKey, nonceTracker }
const pendingKeyExchanges = new Map(); // userId -> { ephemeralPublicKey, timestamp }

export function createE2EERoutes() {
  const router = express.Router();

  // Register user and initiate key exchange
  router.post('/register', (req, res) => {
    const { userId, publicKey } = req.body;
    
    if (!userId || !publicKey) {
      return res.status(400).json({ error: 'userId and publicKey required' });
    }

    // Store user's public key
    userSessions.set(userId, {
      publicKey: new Uint8Array(publicKey),
      sessionKey: null,
      nonceTracker: new Set()
    });

    res.json({ 
      success: true, 
      message: 'User registered',
      userId: userId
    });
  });

  // Initiate key exchange
  router.post('/key-exchange/initiate', (req, res) => {
    const { senderId, receiverId } = req.body;

    if (!senderId || !receiverId) {
      return res.status(400).json({ error: 'senderId and receiverId required' });
    }

    const receiver = userSessions.get(receiverId);
    if (!receiver) {
      return res.status(404).json({ error: 'Receiver not found' });
    }

    // Initiate key exchange
    // Generate a temporary private key for the sender (in production, use actual stored key)
    const senderKeyPair = generateECDHKeyPair();
    const keyExchange = initiateKeyExchange(
      receiver.publicKey,
      senderKeyPair.privateKey
    );
    
    // Store pending exchange
    pendingKeyExchanges.set(senderId, {
      ephemeralPublicKey: Array.from(keyExchange.ephemeralPublicKey),
      sharedSecret: Array.from(keyExchange.sharedSecret),
      receiverId: receiverId,
      timestamp: Date.now()
    });

    res.json({
      success: true,
      ephemeralPublicKey: Array.from(keyExchange.ephemeralPublicKey)
    });
  });

  // Complete key exchange with signature verification
  router.post('/key-exchange/complete', (req, res) => {
    const { senderId, receiverId, ephemeralPublicKey, keyExchangeMessage, signature } = req.body;

    if (!senderId || !receiverId || !ephemeralPublicKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const sender = userSessions.get(senderId);
    if (!sender) {
      return res.status(404).json({ error: 'Sender not found' });
    }

    try {
      // Complete key exchange with signature verification
      const sharedSecret = completeKeyExchange(
        new Uint8Array(ephemeralPublicKey),
        sender.publicKey, // Would be actual private key in production
        sender.publicKey, // Public key for verification
        keyExchangeMessage,
        signature ? new Uint8Array(signature) : null
      );

      // Derive session key
      const salt = generateSalt();
      const sessionKey = deriveSessionKey(
        sharedSecret,
        salt,
        `${senderId}-${receiverId}`
      );

      // Generate key confirmation
      const sessionId = `${senderId}-${receiverId}-${Date.now()}`;
      const keyConfirmation = generateKeyConfirmation(sharedSecret, sessionId);

      // Store session key for both users
      if (!userSessions.has(senderId)) {
        userSessions.set(senderId, { nonceTracker: new Set() });
      }
      if (!userSessions.has(receiverId)) {
        userSessions.set(receiverId, { nonceTracker: new Set() });
      }

      userSessions.get(senderId).sessionKey = Array.from(sessionKey);
      userSessions.get(receiverId).sessionKey = Array.from(sessionKey);

      // Store session metadata in MongoDB
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
        sessionEstablished: true,
        keyConfirmation: keyConfirmation
      });
    } catch (error) {
      // Check if it's a signature verification failure
      if (error.message.includes('signature') || error.message.includes('verification')) {
        logInvalidSignature(senderId, 'key_exchange', {
          receiverId,
          error: error.message,
          ephemeralPublicKey: Array.from(ephemeralPublicKey).slice(0, 10) // Log first 10 bytes only
        });
        
        logSecurityEvent(SecurityEventType.KEY_EXCHANGE_FAILED, {
          senderId,
          receiverId,
          reason: 'signature_verification_failed',
          error: error.message
        });
      } else {
        logSecurityEvent(SecurityEventType.ATTACK_DETECTED, {
          attackType: 'MITM',
          details: error.message,
          senderId,
          receiverId
        });
      }

      res.status(400).json({
        error: 'Key exchange failed',
        details: error.message
      });
    }
  });

  // Verify key confirmation (final step)
  router.post('/key-exchange/confirm', (req, res) => {
    const { senderId, receiverId, sessionId, confirmation, timestamp } = req.body;

    if (!senderId || !receiverId || !sessionId || !confirmation) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const user = userSessions.get(receiverId);
    if (!user || !user.sessionKey) {
      return res.status(400).json({ error: 'Session not established' });
    }

    try {
      // Verify key confirmation
      const sharedSecret = new Uint8Array(32); // Would be actual shared secret
      verifyKeyConfirmation(
        sharedSecret,
        sessionId,
        new Uint8Array(confirmation),
        timestamp
      );

      res.json({
        success: true,
        message: 'Key confirmation verified'
      });
    } catch (error) {
      res.status(400).json({
        error: 'Key confirmation failed',
        details: error.message
      });
    }
  });

  // Send encrypted message
  router.post('/message/send', async (req, res) => {
    const { senderId, receiverId, message } = req.body;

    if (!senderId || !receiverId || !message) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const sender = userSessions.get(senderId);
    if (!sender || !sender.sessionKey) {
      return res.status(400).json({ error: 'Session not established' });
    }

    // Encrypt message
    const sessionKey = new Uint8Array(sender.sessionKey);
    const encrypted = encryptMessage(
      message,
      sessionKey,
      senderId,
      receiverId
    );

    // Store message metadata in MongoDB (NO plaintext)
    const messageId = `${senderId}-${receiverId}-${Date.now()}`;
    await storeMessageMetadata({
      messageId: messageId,
      senderId: senderId,
      receiverId: receiverId,
      timestamp: encrypted.timestamp,
      sequenceNumber: encrypted.sequenceNumber,
      encryptedPayload: encrypted.encryptedPayload,
      iv: encrypted.iv,
      authTag: encrypted.authTag
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
      encryptedMessage: encrypted,
      messageId: messageId
    });
  });

  // Receive and decrypt message
  router.post('/message/receive', (req, res) => {
    const { receiverId, encryptedMessage } = req.body;

    if (!receiverId || !encryptedMessage) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const receiver = userSessions.get(receiverId);
    if (!receiver || !receiver.sessionKey) {
      return res.status(400).json({ error: 'Session not established' });
    }

    try {
      // Verify message (replay protection)
      verifyMessage(encryptedMessage, receiver.nonceTracker);

      // Decrypt message
      const sessionKey = new Uint8Array(receiver.sessionKey);
      const decrypted = decryptMessage(encryptedMessage, sessionKey);

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
  router.post('/file/upload', (req, res) => {
    const { senderId, receiverId, fileName, fileData } = req.body;

    if (!senderId || !receiverId || !fileName || !fileData) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const sender = userSessions.get(senderId);
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
  router.post('/file/download', (req, res) => {
    const { receiverId, encryptedFile } = req.body;

    if (!receiverId || !encryptedFile) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const receiver = userSessions.get(receiverId);
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

