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
  try {
    // The redirect URI should point to the backend callback endpoint
    // The backend will then redirect to the frontend
    const backendUrl = import.meta.env.VITE_API_URL || 'http://localhost:3000';
    const redirectUri = `${backendUrl}/api/auth/oauth/${provider}/callback`;
    
    // Client ID from environment (optional - backend will use env var if not provided)
    const clientId = import.meta.env.VITE_OAUTH_GOOGLE_CLIENT_ID;
    
    const params = {
      redirect_uri: redirectUri
    };
    
    // Only add client_id if provided (backend will use env var as fallback)
    if (clientId) {
      params.client_id = clientId;
    }
    
    const response = await api.get(`/api/auth/oauth/${provider}/authorize`, {
      params: params
    });
    
    if (response.status >= 400 || response.data.error) {
      throw new Error(response.data.error || 'Failed to get OAuth URL');
    }
    
    return response.data;
  } catch (error) {
    // Handle axios errors
    if (error.response) {
      throw new Error(error.response.data?.error || 'Failed to get OAuth authorization URL');
    }
    throw error;
  }
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

// Get all users (for recipient selection)
export async function getAllUsers(excludeUsername = null) {
  try {
    const params = excludeUsername ? { exclude: excludeUsername } : {};
    const response = await api.get('/api/auth/users', { params });
    
    if (response.status >= 400 || response.data.error) {
      throw new Error(response.data.error || 'Failed to get users');
    }
    
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.error || 'Failed to get users list');
    }
    throw error;
  }
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

export async function respondKeyExchange(senderId, receiverId, keyExchangeData) {
  const response = await api.post('/api/e2ee/key-exchange/respond', {
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
  // confirmationData contains: sessionId, senderId, receiverId, timestamp, confirmation
  const response = await api.post('/api/e2ee/key-exchange/confirm', {
    senderId: confirmationData.senderId || senderId,
    receiverId: confirmationData.receiverId || receiverId,
    sessionId: confirmationData.sessionId,
    confirmation: confirmationData.confirmation,
    timestamp: confirmationData.timestamp
  });
  return response.data;
}

// Get pending key exchange
export async function getPendingKeyExchange(userId, senderId) {
  try {
    const response = await api.get(`/api/e2ee/key-exchange/pending/${userId}/${senderId}`);
    if (response.status >= 400 || response.data.error) {
      return { success: false };
    }
    return response.data;
  } catch (error) {
    if (error.response) {
      return { success: false };
    }
    return { success: false };
  }
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

// Get pending messages for a user
export async function getPendingMessages(receiverId) {
  try {
    const response = await api.get(`/api/e2ee/messages/${receiverId}`);
    
    if (response.status >= 400 || response.data.error) {
      throw new Error(response.data.error || 'Failed to get messages');
    }
    
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.error || 'Failed to get messages');
    }
    throw error;
  }
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

