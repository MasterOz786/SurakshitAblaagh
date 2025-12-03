import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import Chat from './components/Chat';
import { initKeyStorage } from './storage/keyStorage.js';
import { generateECKeyPair } from './crypto/webCrypto.js';

function App() {
  const [user, setUser] = useState(null);
  const [keyPair, setKeyPair] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Initialize IndexedDB
    initKeyStorage().then(() => {
      setLoading(false);
    }).catch(err => {
      console.error('Failed to initialize key storage:', err);
      setLoading(false);
    });
  }, []);

  const handleLogin = async (username) => {
    // Generate key pair on login
    const keys = await generateECKeyPair('P-256');
    setKeyPair(keys);
    setUser({ username });
    
    // Store keys in IndexedDB
    const { storeKeyPair } = await import('./storage/keyStorage.js');
    await storeKeyPair(username, {
      privateKey: keys.privateKey,
      publicKey: keys.publicKey,
      type: 'EC'
    });
  };

  const handleLogout = async () => {
    const { clearKeyStorage } = await import('./storage/keyStorage.js');
    await clearKeyStorage();
    setUser(null);
    setKeyPair(null);
  };

  if (loading) {
    return <div>Loading...</div>;
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

