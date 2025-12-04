import React, { useState, useEffect, useRef } from 'react';
import { encryptMessage, decryptMessage, verifyMessage } from '../e2ee/messageClient.js';
import { encryptFile, decryptFile } from '../e2ee/fileClient.js';
import { initiateKeyExchange, completeKeyExchange, generateKeyConfirmation, verifyKeyConfirmation } from '../crypto/keyExchange.js';
import { getSessionKey, storeSessionKey } from '../storage/keyStorage.js';
import { getKeyPair } from '../storage/keyStorage.js';
import { 
  initiateKeyExchange as apiInitiate, 
  completeKeyExchange as apiComplete,
  confirmKeyExchange as apiConfirm,
  sendMessage,
  receiveMessage,
  uploadFile as apiUploadFile,
  downloadFile as apiDownloadFile
} from '../services/api.js';

function Chat({ user, keyPair, onLogout }) {
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [recipient, setRecipient] = useState('');
  const [sessionKey, setSessionKey] = useState(null);
  const [sessionEstablished, setSessionEstablished] = useState(false);
  const [nonceTracker, setNonceTracker] = useState(new Set());
  const [selectedFile, setSelectedFile] = useState(null);
  const fileInputRef = useRef(null);

  // Establish session with recipient
  const establishSession = async (recipientId) => {
    try {
      // Get recipient's public key from server
      const { getUserPublicKey } = await import('../services/api.js');
      const recipientInfo = await getUserPublicKey(recipientId);
      
      if (!recipientInfo || !recipientInfo.publicKey) {
        throw new Error('Recipient not found or has no public key');
      }

      const recipientPublicKey = new Uint8Array(recipientInfo.publicKey);
      
      // Initiate key exchange (client-side)
      const keyExchange = await initiateKeyExchange(
        recipientPublicKey,
        keyPair.privateKey,
        user.username,
        recipientId
      );

      // Send initiation to server
      const initResponse = await apiInitiate(user.username, recipientId, {
        ephemeralPublicKey: Array.from(keyExchange.ephemeralPublicKey),
        keyExchangeMessage: keyExchange.keyExchangeMessage,
        signature: keyExchange.signature
      });

      // Complete key exchange (client-side)
      const completion = await completeKeyExchange(
        initResponse.data.ephemeralPublicKey || keyExchange.ephemeralPublicKey,
        keyPair.privateKey,
        recipientPublicKey,
        keyExchange.keyExchangeMessage,
        keyExchange.signature,
        user.username
      );

      // Send completion to server
      const completeResponse = await apiComplete(user.username, recipientId, {
        sessionKey: Array.from(completion.sessionKey),
        salt: Array.from(completion.salt)
      });

      // Generate key confirmation
      const sessionId = `${user.username}-${recipientId}-${Date.now()}`;
      const confirmation = await generateKeyConfirmation(
        completion.sharedSecret,
        sessionId,
        user.username,
        recipientId
      );

      // Send confirmation
      await apiConfirm(user.username, recipientId, confirmation);

      // Store session key in IndexedDB
      await storeSessionKey(user.username, recipientId, completion.sessionKey);
      setSessionKey(completion.sessionKey);
      setSessionEstablished(true);
    } catch (error) {
      console.error('Failed to establish session:', error);
      alert('Failed to establish session: ' + error.message);
    }
  };

  const sendMessageHandler = async () => {
    if (!inputMessage || !recipient || !sessionKey) {
      alert('Please establish a session first');
      return;
    }

    try {
      // Encrypt message client-side (NO plaintext)
      const encrypted = await encryptMessage(
        inputMessage,
        sessionKey,
        user.username,
        recipient
      );

      // Verify message before sending
      verifyMessage(encrypted, nonceTracker);

      // Send encrypted message (NO plaintext)
      await sendMessage(encrypted);

      // Add to local messages (decrypted for display only)
      setMessages([...messages, {
        sender: user.username,
        receiver: recipient,
        message: inputMessage,
        timestamp: new Date(),
        encrypted: true
      }]);

      setInputMessage('');
    } catch (error) {
      console.error('Failed to send message:', error);
      alert('Failed to send message: ' + error.message);
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const uploadFileHandler = async () => {
    if (!selectedFile || !recipient || !sessionKey) {
      alert('Please select a file and establish a session');
      return;
    }

    try {
      // Encrypt file client-side (NO plaintext)
      const encryptedFile = await encryptFile(selectedFile, sessionKey);

      // Upload encrypted file (NO plaintext)
      await apiUploadFile({
        senderId: user.username,
        receiverId: recipient,
        ...encryptedFile
      });

      alert('File uploaded successfully');
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } catch (error) {
      console.error('Failed to upload file:', error);
      alert('Failed to upload file: ' + error.message);
    }
  };

  return (
    <div className="chat-container">
      <div className="chat-header">
        <h2>Welcome, {user.username}</h2>
        <button 
          onClick={onLogout}
          className="logout-button"
        >
          Logout
        </button>
      </div>
      
      <div className="recipient-selector">
        <input
          type="text"
          placeholder="Recipient username"
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
        />
        <button 
          onClick={() => establishSession(recipient)}
          disabled={!recipient || sessionEstablished}
        >
          {sessionEstablished ? 'Session Established' : 'Start Session'}
        </button>
      </div>

      {sessionEstablished && (
        <div className="session-status">
          ✓ Secure session established with {recipient}
        </div>
      )}

      <div className="messages">
        {messages.map((msg, idx) => (
          <div key={idx} className="message">
            <strong>{msg.sender}:</strong> {msg.message}
            <span className="timestamp">{new Date(msg.timestamp).toLocaleTimeString()}</span>
          </div>
        ))}
      </div>

      <div className="file-upload">
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileSelect}
        />
        {selectedFile && (
          <div>
            Selected: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(2)} KB)
            <button onClick={uploadFileHandler}>Upload Encrypted File</button>
          </div>
        )}
      </div>

      <div className="message-input">
        <input
          type="text"
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && sendMessageHandler()}
          placeholder="Type a message..."
          disabled={!sessionEstablished}
        />
        <button onClick={sendMessageHandler} disabled={!sessionEstablished}>
          Send
        </button>
      </div>
    </div>
  );
}

export default Chat;
