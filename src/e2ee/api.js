/**
 * Express API routes for E2EE messaging system
 */

import express from 'express';
import { encryptMessage, decryptMessage, verifyMessage } from './message.js';
import { encryptFile, decryptFile } from './fileHandler.js';
import { initiateKeyExchange, completeKeyExchange, deriveSessionKey } from './keyExchange.js';
import { generateSalt } from './crypto.js';

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
    const keyExchange = initiateKeyExchange(receiver.publicKey);
    
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

  // Complete key exchange
  router.post('/key-exchange/complete', (req, res) => {
    const { senderId, receiverId, ephemeralPublicKey } = req.body;

    if (!senderId || !receiverId || !ephemeralPublicKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const sender = userSessions.get(senderId);
    if (!sender) {
      return res.status(404).json({ error: 'Sender not found' });
    }

    // Complete key exchange
    const sharedSecret = completeKeyExchange(
      new Uint8Array(ephemeralPublicKey),
      sender.publicKey // Using as private key for demo (in production, use actual private key)
    );

    // Derive session key
    const salt = generateSalt();
    const sessionKey = deriveSessionKey(
      sharedSecret,
      salt,
      `${senderId}-${receiverId}`
    );

    // Store session key for both users
    if (!userSessions.has(senderId)) {
      userSessions.set(senderId, { nonceTracker: new Set() });
    }
    if (!userSessions.has(receiverId)) {
      userSessions.set(receiverId, { nonceTracker: new Set() });
    }

    userSessions.get(senderId).sessionKey = Array.from(sessionKey);
    userSessions.get(receiverId).sessionKey = Array.from(sessionKey);

    res.json({
      success: true,
      message: 'Key exchange completed',
      sessionEstablished: true
    });
  });

  // Send encrypted message
  router.post('/message/send', (req, res) => {
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

    res.json({
      success: true,
      encryptedMessage: encrypted
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

      res.json({
        success: true,
        message: decrypted
      });
    } catch (error) {
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

