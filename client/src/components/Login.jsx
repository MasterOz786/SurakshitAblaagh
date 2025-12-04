import React, { useState } from 'react';
import { registerUser, loginUser, getOAuthUrl } from '../services/api.js';
import { generateECKeyPair } from '../crypto/webCrypto.js';
import { storeKeyPair } from '../storage/keyStorage.js';
import { registerE2EEUser } from '../services/api.js';

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegister, setIsRegister] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleOAuthLogin = async (provider = 'google') => {
    try {
      setError('');
      setLoading(true);
      
      const { authorizationUrl } = await getOAuthUrl(provider);
      
      if (!authorizationUrl) {
        throw new Error('Failed to get OAuth authorization URL');
      }
      
      // Redirect to OAuth provider
      window.location.href = authorizationUrl;
      // Note: setLoading(false) won't execute because page redirects
    } catch (err) {
      const errorMessage = err.response?.data?.error || err.message || 'OAuth login failed';
      setError(errorMessage);
      console.error('OAuth login error:', errorMessage);
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isRegister) {
        // Register user
        await registerUser(username, password);
        
        // Generate key pair (client-side only)
        const keyPair = await generateECKeyPair('P-256');
        
        // Store private key in IndexedDB (never sent to server)
        await storeKeyPair(username, {
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
          type: 'EC'
        });
        
        // Register E2EE user (send public key only)
        await registerE2EEUser(username, keyPair.publicKey);
        
        setError('Registration successful! Please login.');
        setIsRegister(false);
      } else {
        // Login - verify credentials first
        const loginResult = await loginUser(username, password);
        
        // Only proceed if login was successful
        if (!loginResult || !loginResult.success) {
          throw new Error('Authentication failed');
        }
        
        // Load key pair from IndexedDB
        const { getKeyPair } = await import('../storage/keyStorage.js');
        const keyPair = await getKeyPair(username);
        
        if (!keyPair) {
          // Generate if not found
          const newKeyPair = await generateECKeyPair('P-256');
          await storeKeyPair(username, {
            privateKey: newKeyPair.privateKey,
            publicKey: newKeyPair.publicKey,
            type: 'EC'
          });
          await registerE2EEUser(username, newKeyPair.publicKey);
          onLogin(username, newKeyPair);
        } else {
          onLogin(username, keyPair);
        }
      }
    } catch (err) {
      const errorMessage = err.response?.data?.error || err.message || 'Authentication failed';
      setError(errorMessage);
      console.error('Authentication error:', errorMessage);
      // Don't proceed with login on error
      return;
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <h1>SurakshitAblaagh E2EE Messaging</h1>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
          disabled={loading}
        />
        <input
          type="password"
          placeholder="Password (min 8 characters)"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={8}
          disabled={loading}
        />
        {error && <div className="error">{error}</div>}
        <button type="submit" disabled={loading}>
          {loading ? 'Processing...' : (isRegister ? 'Register' : 'Login')}
        </button>
        <button 
          type="button" 
          onClick={() => setIsRegister(!isRegister)}
          disabled={loading}
        >
          {isRegister ? 'Already have an account? Login' : 'Need an account? Register'}
        </button>
      </form>
      
      <div className="oauth-divider">
        <p>Or continue with</p>
        <button
          type="button"
          onClick={() => handleOAuthLogin('google')}
          disabled={loading}
          className="oauth-button"
        >
          <svg width="20" height="20" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          Continue with Google
        </button>
      </div>
    </div>
  );
}

export default Login;
