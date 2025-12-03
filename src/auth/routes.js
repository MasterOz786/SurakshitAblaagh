/**
 * Authentication API Routes
 */

import express from 'express';
import { registerUser, authenticateUser, getUser } from './auth.js';
import { logSecurityEvent, SecurityEventType } from '../security/logging.js';

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

      const result = await registerUser(username, password);
      
      logSecurityEvent(SecurityEventType.SESSION_ESTABLISHED, {
        username: username,
        action: 'registration'
      });

      res.status(201).json(result);
    } catch (error) {
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

      const result = await authenticateUser(username, password);
      
      logSecurityEvent(SecurityEventType.SESSION_ESTABLISHED, {
        username: username,
        action: 'login'
      });

      res.json(result);
    } catch (error) {
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

  return router;
}

