/**
 * OAuth 2.0 Authentication Module
 * Supports Google OAuth and can be extended for other providers
 */

import { registerUser, getUser, userExists } from './auth.js';
import { logSecurityEvent, SecurityEventType, logAuthenticationAttempt } from '../security/logging.js';

// OAuth provider configurations
const OAUTH_PROVIDERS = {
  google: {
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
    scope: 'openid email profile'
  }
};

// Store OAuth state for CSRF protection
const oauthStates = new Map();

// Generate OAuth state token
export function generateOAuthState() {
  const state = crypto.randomUUID ? crypto.randomUUID() : generateRandomString(32);
  oauthStates.set(state, {
    timestamp: Date.now(),
    provider: 'google'
  });
  
  // Clean up old states (older than 10 minutes)
  const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
  for (const [key, value] of oauthStates.entries()) {
    if (value.timestamp < tenMinutesAgo) {
      oauthStates.delete(key);
    }
  }
  
  return state;
}

// Verify OAuth state
export function verifyOAuthState(state) {
  const stateData = oauthStates.get(state);
  if (!stateData) {
    return false;
  }
  
  // Check if state is not too old (10 minutes)
  const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
  if (stateData.timestamp < tenMinutesAgo) {
    oauthStates.delete(state);
    return false;
  }
  
  // Delete used state
  oauthStates.delete(state);
  return true;
}

// Generate random string for state
function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Get OAuth authorization URL
export function getOAuthUrl(provider = 'google', redirectUri, clientId) {
  const config = OAUTH_PROVIDERS[provider];
  if (!config) {
    throw new Error(`Unsupported OAuth provider: ${provider}`);
  }
  
  const state = generateOAuthState();
  
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: config.scope,
    state: state,
    access_type: 'offline',
    prompt: 'consent'
  });
  
  return {
    url: `${config.authUrl}?${params.toString()}`,
    state: state
  };
}

// Exchange authorization code for access token
export async function exchangeCodeForToken(provider, code, redirectUri, clientId, clientSecret) {
  const config = OAUTH_PROVIDERS[provider];
  if (!config) {
    throw new Error(`Unsupported OAuth provider: ${provider}`);
  }
  
  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      code: code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    })
  });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Token exchange failed' }));
    throw new Error(error.error || 'Failed to exchange code for token');
  }
  
  return await response.json();
}

// Get user info from OAuth provider
export async function getOAuthUserInfo(provider, accessToken) {
  const config = OAUTH_PROVIDERS[provider];
  if (!config) {
    throw new Error(`Unsupported OAuth provider: ${provider}`);
  }
  
  const response = await fetch(config.userInfoUrl, {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  if (!response.ok) {
    throw new Error('Failed to get user info from OAuth provider');
  }
  
  return await response.json();
}

// Authenticate or register user via OAuth
export async function authenticateWithOAuth(provider, userInfo) {
  // Create username from OAuth email (sanitized)
  const email = userInfo.email;
  const username = email.split('@')[0] + '_' + provider;
  
  // Check if user exists
  let user = getUser(username);
  
  if (!user) {
    // Register new user (no password needed for OAuth)
    // Generate a random password that will never be used
    const randomPassword = generateRandomString(32);
    
    try {
      await registerUser(username, randomPassword);
      user = getUser(username);
      
      // Mark user as OAuth user
      if (user) {
        user.oauthProvider = provider;
        user.oauthId = userInfo.id;
        user.email = email;
        user.name = userInfo.name;
        user.picture = userInfo.picture;
      }
      
      logSecurityEvent(SecurityEventType.SESSION_ESTABLISHED, {
        username: username,
        action: 'oauth_registration',
        provider: provider
      });
    } catch (error) {
      throw new Error('Failed to register OAuth user');
    }
  } else {
    // Update OAuth info for existing user
    user.oauthProvider = provider;
    user.oauthId = userInfo.id;
    user.email = email;
    user.name = userInfo.name;
    user.picture = userInfo.picture;
  }
  
  // Log successful authentication
  logAuthenticationAttempt(username, true);
  logSecurityEvent(SecurityEventType.SESSION_ESTABLISHED, {
    username: username,
    action: 'oauth_login',
    provider: provider
  });
  
  return {
    success: true,
    username: username,
    email: email,
    name: userInfo.name,
    picture: userInfo.picture,
    provider: provider,
    lastLogin: new Date()
  };
}

