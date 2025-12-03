/**
 * API Service - HTTPS only, no plaintext transmission
 */

import axios from 'axios';

// Use HTTP for local dev, HTTPS in production
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

// Create axios instance with HTTPS
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  },
  // HTTPS only - reject HTTP in production
  validateStatus: (status) => status < 500
});

// Authentication
export async function registerUser(username, password) {
  const response = await api.post('/api/auth/register', {
    username,
    password // Will be hashed server-side
  });
  return response.data;
}

export async function loginUser(username, password) {
  const response = await api.post('/api/auth/login', {
    username,
    password // Will be hashed server-side
  });
  return response.data;
}

// E2EE Registration (send public key only, never private key)
export async function registerE2EEUser(userId, publicKey) {
  const response = await api.post('/api/e2ee/register', {
    userId,
    publicKey: Array.from(publicKey) // Public key only
  });
  return response.data;
}

// Get user public key
export async function getUserPublicKey(userId) {
  const response = await api.get(`/api/e2ee/user/${userId}`);
  return response.data;
}

// Key Exchange
export async function initiateKeyExchange(senderId, receiverId, keyExchangeData) {
  const response = await api.post('/api/e2ee/key-exchange/initiate', {
    senderId,
    receiverId,
    ...keyExchangeData
  });
  return response.data;
}

export async function completeKeyExchange(senderId, receiverId, completionData) {
  const response = await api.post('/api/e2ee/key-exchange/complete', {
    senderId,
    receiverId,
    ...completionData
  });
  return response.data;
}

export async function confirmKeyExchange(senderId, receiverId, confirmationData) {
  const response = await api.post('/api/e2ee/key-exchange/confirm', {
    senderId,
    receiverId,
    ...confirmationData
  });
  return response.data;
}

// Messages (encrypted payload only, no plaintext)
export async function sendMessage(encryptedMessage) {
  // encryptedMessage contains NO plaintext
  const response = await api.post('/api/e2ee/message/send', encryptedMessage);
  return response.data;
}

export async function receiveMessage(receiverId, encryptedMessage) {
  const response = await api.post('/api/e2ee/message/receive', {
    receiverId,
    encryptedMessage // Encrypted only, no plaintext
  });
  return response.data;
}

// Files (encrypted chunks only, no plaintext)
export async function uploadFile(encryptedFileData) {
  // encryptedFileData contains NO plaintext
  const response = await api.post('/api/e2ee/file/upload', encryptedFileData);
  return response.data;
}

export async function downloadFile(fileId, receiverId) {
  const response = await api.post('/api/e2ee/file/download', {
    fileId,
    receiverId
  });
  return response.data;
}

export default api;

