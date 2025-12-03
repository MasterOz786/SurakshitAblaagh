import React, { useState } from 'react';
import { registerUser, loginUser } from '../services/api.js';
import { generateECKeyPair } from '../crypto/webCrypto.js';
import { storeKeyPair } from '../storage/keyStorage.js';
import { registerE2EEUser } from '../services/api.js';

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegister, setIsRegister] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

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
        // Login
        await loginUser(username, password);
        
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
      setError(err.response?.data?.error || err.message || 'Authentication failed');
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
    </div>
  );
}

export default Login;
