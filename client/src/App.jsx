import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import Chat from './components/Chat';
import { initKeyStorage } from './storage/keyStorage.js';
import { generateECKeyPair } from './crypto/webCrypto.js';
import { storeKeyPair, getKeyPair } from './storage/keyStorage.js';
import { registerE2EEUser } from './services/api.js';

function App() {
  const [user, setUser] = useState(null);
  const [keyPair, setKeyPair] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Initialize IndexedDB
    initKeyStorage().then(() => {
      setLoading(false);
      
      // Check for OAuth callback
      const searchParams = new URLSearchParams(window.location.search);
      const success = searchParams.get('success');
      
      if (success === 'true') {
        handleOAuthCallback(searchParams);
      } else if (success === 'false') {
        const error = searchParams.get('error');
        const errorMessage = error || 'OAuth authentication was cancelled or failed';
        console.error('OAuth error:', errorMessage);
        // Show user-friendly error message
        alert(errorMessage);
        // Clear URL params
        window.history.replaceState({}, document.title, window.location.pathname);
      }
    }).catch(err => {
      console.error('Failed to initialize key storage:', err);
      setLoading(false);
    });
  }, []);

  const handleOAuthCallback = async (searchParams) => {
    try {
      setLoading(true);
      
      const username = searchParams.get('username');
      const email = searchParams.get('email');
      const name = searchParams.get('name');
      const provider = searchParams.get('provider');
      
      if (!username) {
        throw new Error('OAuth callback missing username');
      }
      
      // Load or generate key pair
      let keys = await getKeyPair(username);
      
      if (!keys) {
        // Generate new key pair for OAuth user
        keys = await generateECKeyPair('P-256');
        await storeKeyPair(username, {
          privateKey: keys.privateKey,
          publicKey: keys.publicKey,
          type: 'EC'
        });
        await registerE2EEUser(username, keys.publicKey);
      }
      
      // Set user and keys
      setUser({ username, email, name, provider });
      setKeyPair(keys);
      
      // Clear URL params
      window.history.replaceState({}, document.title, window.location.pathname);
      setLoading(false);
    } catch (error) {
      console.error('OAuth callback error:', error);
      alert('OAuth login failed: ' + error.message);
      // Clear URL params
      window.history.replaceState({}, document.title, window.location.pathname);
      setLoading(false);
    }
  };

  const handleLogin = async (username, keys) => {
    setKeyPair(keys);
    setUser({ username });
  };

  const handleLogout = async () => {
    const { clearKeyStorage } = await import('./storage/keyStorage.js');
    await clearKeyStorage();
    setUser(null);
    setKeyPair(null);
  };

  if (loading) {
    return <div className="loading">Initializing secure storage...</div>;
  }

  return (
    <div className="app">
      {!user ? (
        <Login onLogin={handleLogin} />
      ) : (
        <Chat user={user} keyPair={keyPair} onLogout={handleLogout} />
      )}
    </div>
  );
}

export default App;
