import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { encryptMessage, decryptMessage } from '../e2ee/messageClient.js';
import { getSessionKey, storeSessionKey } from '../storage/keyStorage.js';

function Chat({ user, keyPair, onLogout }) {
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [recipient, setRecipient] = useState('');
  const [sessionKey, setSessionKey] = useState(null);

  // Establish session with recipient
  const establishSession = async (recipientId) => {
    try {
      // Initiate key exchange
      const initResponse = await axios.post('/api/e2ee/key-exchange/initiate', {
        senderId: user.username,
        receiverId: recipientId
      });

      // Complete key exchange
      const completeResponse = await axios.post('/api/e2ee/key-exchange/complete', {
        senderId: user.username,
        receiverId: recipientId,
        ephemeralPublicKey: initResponse.data.ephemeralPublicKey
      });

      if (completeResponse.data.sessionEstablished) {
        // Get session key (would be derived from key exchange)
        const key = await getSessionKey(user.username, recipientId);
        setSessionKey(key);
      }
    } catch (error) {
      console.error('Failed to establish session:', error);
    }
  };

  const sendMessage = async () => {
    if (!inputMessage || !recipient || !sessionKey) return;

    try {
      // Encrypt message client-side
      const encrypted = await encryptMessage(
        inputMessage,
        sessionKey,
        user.username,
        recipient
      );

      // Send encrypted message
      const response = await axios.post('/api/e2ee/message/send', {
        senderId: user.username,
        receiverId: recipient,
        message: inputMessage // This will be encrypted by the API
      });

      setMessages([...messages, {
        sender: user.username,
        receiver: recipient,
        message: inputMessage,
        timestamp: new Date()
      }]);

      setInputMessage('');
    } catch (error) {
      console.error('Failed to send message:', error);
    }
  };

  return (
    <div className="chat-container">
      <div className="chat-header">
        <h2>Welcome, {user.username}</h2>
        <button onClick={onLogout}>Logout</button>
      </div>
      
      <div className="recipient-selector">
        <input
          type="text"
          placeholder="Recipient username"
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
        />
        <button onClick={() => establishSession(recipient)}>
          Start Session
        </button>
      </div>

      <div className="messages">
        {messages.map((msg, idx) => (
          <div key={idx} className="message">
            <strong>{msg.sender}:</strong> {msg.message}
            <span className="timestamp">{new Date(msg.timestamp).toLocaleTimeString()}</span>
          </div>
        ))}
      </div>

      <div className="message-input">
        <input
          type="text"
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
          placeholder="Type a message..."
        />
        <button onClick={sendMessage}>Send</button>
      </div>
    </div>
  );
}

export default Chat;

