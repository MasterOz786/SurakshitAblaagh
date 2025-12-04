/**
 * Authentication API Routes
 */

import express from 'express';
import { registerUser, authenticateUser, getUser } from './auth.js';
import { 
  logSecurityEvent, 
  SecurityEventType,
  logAuthenticationAttempt
} from '../security/logging.js';
import {
  getOAuthUrl,
  verifyOAuthState,
  exchangeCodeForToken,
  getOAuthUserInfo,
  authenticateWithOAuth
} from './oauth.js';

export function createAuthRoutes() {
  const router = express.Router();

  // Register new user
  router.post('/register', async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
      }

      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
      }

      // Log registration attempt
      logSecurityEvent(SecurityEventType.AUTHENTICATION_ATTEMPT, {
        username: username,
        action: 'registration',
        timestamp: Date.now()
      });

      const result = await registerUser(username, password);
      
      // Log successful registration
      logAuthenticationAttempt(username, true);
      logSecurityEvent(SecurityEventType.SESSION_ESTABLISHED, {
        username: username,
        action: 'registration'
      });

      res.status(201).json(result);
    } catch (error) {
      // Log failed registration
      logAuthenticationAttempt(username || 'unknown', false);
      logSecurityEvent(SecurityEventType.AUTHENTICATION_FAILED, {
        error: error.message,
        action: 'registration'
      });

      res.status(400).json({ error: error.message });
    }
  });

  // Login
  router.post('/login', async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
      }

      // Log authentication attempt
      logSecurityEvent(SecurityEventType.AUTHENTICATION_ATTEMPT, {
        username: username,
        action: 'login',
        timestamp: Date.now()
      });

      const result = await authenticateUser(username, password);
      
      // Log successful authentication
      logAuthenticationAttempt(username, true);
      logSecurityEvent(SecurityEventType.SESSION_ESTABLISHED, {
        username: username,
        action: 'login'
      });

      res.json(result);
    } catch (error) {
      // Log failed authentication
      logAuthenticationAttempt(req.body.username || 'unknown', false);
      logSecurityEvent(SecurityEventType.AUTHENTICATION_FAILED, {
        username: req.body.username,
        error: error.message,
        action: 'login'
      });

      res.status(401).json({ error: error.message });
    }
  });

  // Get user info
  router.get('/user/:username', (req, res) => {
    const { username } = req.params;
    const user = getUser(username);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  });

  // OAuth Routes
  // Get OAuth authorization URL
  router.get('/oauth/:provider/authorize', (req, res) => {
    try {
      const { provider } = req.params;
      const { redirect_uri, client_id } = req.query;

      if (!redirect_uri || !client_id) {
        return res.status(400).json({ error: 'redirect_uri and client_id required' });
      }

      const { url, state } = getOAuthUrl(provider, redirect_uri, client_id);

      res.json({
        authorizationUrl: url,
        state: state
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  // OAuth callback - exchange code for token and authenticate
  router.get('/oauth/:provider/callback', async (req, res) => {
    try {
      const { provider } = req.params;
      const { code, state, redirect_uri } = req.query;

      if (!code || !state) {
        return res.status(400).json({ error: 'code and state required' });
      }

      // Verify state
      if (!verifyOAuthState(state)) {
        logSecurityEvent(SecurityEventType.AUTHENTICATION_FAILED, {
          error: 'Invalid OAuth state',
          action: 'oauth_callback'
        });
        return res.status(400).json({ error: 'Invalid state parameter' });
      }

      // Get OAuth credentials from environment
      const clientId = process.env[`OAUTH_${provider.toUpperCase()}_CLIENT_ID`] || req.query.client_id;
      const clientSecret = process.env[`OAUTH_${provider.toUpperCase()}_CLIENT_SECRET`] || req.query.client_secret;
      const callbackUri = redirect_uri || `${req.protocol}://${req.get('host')}/api/auth/oauth/${provider}/callback`;

      if (!clientId || !clientSecret) {
        return res.status(500).json({ error: 'OAuth credentials not configured' });
      }

      // Exchange code for token
      const tokenData = await exchangeCodeForToken(provider, code, callbackUri, clientId, clientSecret);

      // Get user info
      const userInfo = await getOAuthUserInfo(provider, tokenData.access_token);

      // Authenticate or register user
      const authResult = await authenticateWithOAuth(provider, userInfo);

      // Redirect to frontend with token (in production, use secure session)
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
      const redirectUrl = `${frontendUrl}/oauth/callback?success=true&username=${encodeURIComponent(authResult.username)}&email=${encodeURIComponent(authResult.email)}&name=${encodeURIComponent(authResult.name || '')}&provider=${provider}`;

      res.redirect(redirectUrl);
    } catch (error) {
      logSecurityEvent(SecurityEventType.AUTHENTICATION_FAILED, {
        error: error.message,
        action: 'oauth_callback',
        provider: req.params.provider
      });

      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
      const redirectUrl = `${frontendUrl}/oauth/callback?success=false&error=${encodeURIComponent(error.message)}`;
      res.redirect(redirectUrl);
    }
  });

  return router;
}

