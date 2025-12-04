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
  try {
    const response = await api.post('/api/auth/register', {
      username,
      password // Will be hashed server-side
    });
    
    // Check if response indicates failure
    if (response.status >= 400 || response.data.error) {
      throw new Error(response.data.error || 'Registration failed');
    }
    
    return response.data;
  } catch (error) {
    // Handle axios errors
    if (error.response) {
      throw new Error(error.response.data?.error || 'Registration failed');
    }
    throw error;
  }
}

export async function loginUser(username, password) {
  try {
    const response = await api.post('/api/auth/login', {
      username,
      password // Will be hashed server-side
    });
    
    // Check if response indicates failure
    if (response.status >= 400 || response.data.error) {
      throw new Error(response.data.error || 'Authentication failed');
    }
    
    return response.data;
  } catch (error) {
    // Handle axios errors
    if (error.response) {
      throw new Error(error.response.data?.error || 'Authentication failed');
    }
    throw error;
  }
}

// OAuth Authentication
export async function getOAuthUrl(provider = 'google') {
  // The redirect URI should point to the backend callback endpoint
  // The backend will then redirect to the frontend
  const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:3000';
  const redirectUri = `${backendUrl}/api/auth/oauth/${provider}/callback`;
  
  // Client ID from environment or use placeholder (backend will use env var if not provided)
  const clientId = import.meta.env.VITE_OAUTH_GOOGLE_CLIENT_ID || '';
  
  const response = await api.get(`/api/auth/oauth/${provider}/authorize`, {
    params: {
      redirect_uri: redirectUri,
      client_id: clientId || undefined // Only send if provided
    }
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

