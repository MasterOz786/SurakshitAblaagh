import React, { useState, useEffect, useRef } from 'react';
import { encryptMessage, decryptMessage, verifyMessage, resetLastReceivedSequence, getLastReceivedSequence } from '../e2ee/messageClient.js';
import { encryptFile, decryptFile } from '../e2ee/fileClient.js';
import { generateKeyConfirmation, verifyKeyConfirmation, completeKeyExchangeBidirectional } from '../crypto/keyExchange.js';
import { getSessionKey, storeSessionKey, getAllSessions, deleteSession } from '../storage/keyStorage.js';
import { getKeyPair } from '../storage/keyStorage.js';
import { 
  initiateKeyExchange as apiInitiate, 
  respondKeyExchange as apiRespond,
  completeKeyExchange as apiComplete,
  confirmKeyExchange as apiConfirm,
  getPendingKeyExchange,
  sendMessage,
  receiveMessage,
  getPendingMessages,
  uploadFile as apiUploadFile,
  downloadFile as apiDownloadFile,
  getAllUsers
} from '../services/api.js';

function Chat({ user, keyPair, onLogout }) {
  // Multiple sessions support: Map of recipientId -> { sessionKey, messages, nonceTracker, establishedAt }
  const [sessions, setSessions] = useState(new Map());
  const [activeRecipient, setActiveRecipient] = useState('');
  const [inputMessage, setInputMessage] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const fileInputRef = useRef(null);
  const [sessionKeyMismatchUsers, setSessionKeyMismatchUsers] = useState(new Set());
  const [undecryptableMessages, setUndecryptableMessages] = useState(new Map()); // recipientId -> count
  const [showDebugPanel, setShowDebugPanel] = useState(false);
  const [establishingSession, setEstablishingSession] = useState(new Set()); // Track which sessions are being established
  const [indexedDBSessionKeys, setIndexedDBSessionKeys] = useState(new Map()); // recipientId -> sessionKey from IndexedDB
  const [sessionsLoaded, setSessionsLoaded] = useState(false); // Track if sessions have been loaded from IndexedDB
  const [openChats, setOpenChats] = useState(new Set()); // Track which chat cards are open
  const [minimizedChats, setMinimizedChats] = useState(new Set()); // Track which chats are minimized
  const [availableUsers, setAvailableUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  
  // Use refs to avoid stale closures
  const sessionsRef = useRef(new Map());
  const loadingMessagesRef = useRef(new Set());
  const activeRecipientRef = useRef('');
  
  // Keep refs in sync with state
  useEffect(() => {
    sessionsRef.current = sessions;
  }, [sessions]);
  
  useEffect(() => {
    activeRecipientRef.current = activeRecipient;
  }, [activeRecipient]);

  // Load existing sessions on mount - CRITICAL: Must complete before any other operations
  useEffect(() => {
    loadExistingSessions();
    loadAllUsers();
  }, []);

  // Load all users
  const loadAllUsers = async () => {
    setLoadingUsers(true);
    try {
      const response = await getAllUsers(user.username);
      setAvailableUsers(response.users || []);
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      setLoadingUsers(false);
    }
  };

  // Start chat with user
  const startChatWithUser = async (username) => {
    // If session already exists, just open it
    if (sessions.has(username)) {
      setActiveRecipient(username);
      activeRecipientRef.current = username;
      setOpenChats(prev => {
        const newSet = new Set(prev);
        newSet.add(username);
        return newSet;
      });
      return;
    }
    
    // Check if session exists in IndexedDB
    try {
      const sessionKeyFromDB = await getSessionKey(user.username, username);
      if (sessionKeyFromDB) {
        setSessions(prevSessions => {
          const newSessions = new Map(prevSessions);
          newSessions.set(username, {
            sessionKey: sessionKeyFromDB,
            messages: [],
            nonceTracker: new Set(),
            establishedAt: Date.now()
          });
          sessionsRef.current = newSessions;
          return newSessions;
        });
        setActiveRecipient(username);
        activeRecipientRef.current = username;
        setOpenChats(prev => {
          const newSet = new Set(prev);
          newSet.add(username);
          return newSet;
        });
        await loadPendingMessages(username, sessionKeyFromDB, false);
        return;
      }
    } catch (error) {
      // Continue to establish new session
    }
    
    // Start new session
    if (!establishingSession.has(username)) {
      await establishSession(username);
    }
  };

  // Auto-load messages when activeRecipient changes and session exists
  useEffect(() => {
    if (!sessionsLoaded) return; // Wait for sessions to be loaded
    
    if (activeRecipient && sessions.has(activeRecipient)) {
      const session = sessions.get(activeRecipient);
      if (session && session.sessionKey) {
        // Prevent duplicate loads
        if (!loadingMessagesRef.current.has(activeRecipient)) {
          loadingMessagesRef.current.add(activeRecipient);
          loadPendingMessages(activeRecipient, session.sessionKey, false).finally(() => {
            loadingMessagesRef.current.delete(activeRecipient);
          });
        }
      }
    }
  }, [activeRecipient, sessionsLoaded]);

  // Auto-poll for new messages every 3 seconds when there's an active session
  useEffect(() => {
    if (!sessionsLoaded) return; // Wait for sessions to be loaded
    if (!activeRecipient) return; // No active recipient
    
    // Verify session exists in both state and IndexedDB before polling
    const verifyAndPoll = async () => {
      // Check if session exists in state
      const currentSessions = sessionsRef.current;
      if (!currentSessions.has(activeRecipient)) {
        // Session doesn't exist in state, try to load from IndexedDB
        try {
          const sessionKeyFromDB = await getSessionKey(user.username, activeRecipient);
          if (sessionKeyFromDB) {
            // Session exists in IndexedDB but not in state - restore it
            setSessions(prevSessions => {
              const newSessions = new Map(prevSessions);
              newSessions.set(activeRecipient, {
                sessionKey: sessionKeyFromDB,
                messages: [],
                nonceTracker: new Set(),
                establishedAt: Date.now() // We don't know the actual time
              });
              sessionsRef.current = newSessions;
              return newSessions;
            });
          } else {
            // Session doesn't exist anywhere - stop polling
            return;
          }
        } catch (error) {
          console.error('Failed to verify session:', error);
          return;
        }
      }

      // Session exists, proceed with polling
      if (!loadingMessagesRef.current.has(activeRecipient)) {
        try {
          // Always get session key from IndexedDB first (source of truth)
          const sessionKeyFromDB = await getSessionKey(user.username, activeRecipient);
          if (sessionKeyFromDB) {
            // Update session in state if key changed
            setSessions(prevSessions => {
              const newSessions = new Map(prevSessions);
              const currentSession = newSessions.get(activeRecipient);
              if (currentSession) {
                // Check if keys are different (compare byte by byte)
                const keysMatch = currentSession.sessionKey && 
                  currentSession.sessionKey.length === sessionKeyFromDB.length &&
                  Array.from(currentSession.sessionKey).every((b, i) => b === sessionKeyFromDB[i]);
                
                if (!keysMatch) {
                  // Key changed, update it
                newSessions.set(activeRecipient, {
                  ...currentSession,
                  sessionKey: sessionKeyFromDB
                });
                  sessionsRef.current = newSessions;
                return newSessions;
                }
              }
              return prevSessions; // No change needed
            });
            
            loadingMessagesRef.current.add(activeRecipient);
            await loadPendingMessages(activeRecipient, sessionKeyFromDB, false); // false = auto-polling
            loadingMessagesRef.current.delete(activeRecipient);
          } else {
            // No session key in IndexedDB - session was deleted, remove from state
            setSessions(prevSessions => {
              const newSessions = new Map(prevSessions);
              newSessions.delete(activeRecipient);
              sessionsRef.current = newSessions;
              return newSessions;
            });
            // Clear active recipient if it was deleted
            if (activeRecipientRef.current === activeRecipient) {
              setActiveRecipient('');
            }
          }
        } catch (error) {
          console.error('Failed to poll messages:', error);
          loadingMessagesRef.current.delete(activeRecipient);
        }
      }
    };

    // Poll immediately
    verifyAndPoll();

    // Set up interval for polling
    const intervalId = setInterval(verifyAndPoll, 3000); // Poll every 3 seconds

    // Cleanup on unmount or when activeRecipient changes
    return () => {
      clearInterval(intervalId);
    };
  }, [activeRecipient, sessionsLoaded, user.username]);

  // Load all existing sessions from IndexedDB
  const loadExistingSessions = async () => {
    try {
      const existingSessions = await getAllSessions(user.username);
      const sessionsMap = new Map();
      
      for (const session of existingSessions) {
        if (session.sessionKey) {
        sessionsMap.set(session.peerUserId, {
          sessionKey: session.sessionKey,
          messages: [],
          nonceTracker: new Set(),
            establishedAt: session.establishedAt || Date.now()
        });
        }
      }
      
      setSessions(sessionsMap);
      sessionsRef.current = sessionsMap;
      
      if (sessionsMap.size > 0 && !activeRecipient) {
        const firstRecipient = Array.from(sessionsMap.keys())[0];
        setActiveRecipient(firstRecipient);
        activeRecipientRef.current = firstRecipient;
      }
      
      setSessionsLoaded(true);
      
      // Load messages for all sessions
      for (const [peerUserId, session] of sessionsMap) {
        if (session.sessionKey) {
          await loadPendingMessages(peerUserId, session.sessionKey, false);
        }
      }
    } catch (error) {
      console.error('Failed to load sessions:', error);
      setSessionsLoaded(true);
    }
  };

  // Get current session data
  const getCurrentSession = () => {
    if (!activeRecipient) return null;
    return sessions.get(activeRecipient);
  };

  // Get current messages
  const getCurrentMessages = () => {
    const session = getCurrentSession();
    if (!session) {
      return [];
    }
    return session.messages || [];
  };


  // Establish session with recipient
  const establishSession = async (recipientId) => {
    // Validate recipient ID
    if (!recipientId || recipientId.trim() === '') {
      alert('Please enter a recipient username');
      return;
    }

    // Check if session already exists in state
    if (sessions.has(recipientId)) {
      setActiveRecipient(recipientId);
      return;
    }

    if (establishingSession.has(recipientId)) {
      return;
    }
    
    setEstablishingSession(prev => new Set(prev).add(recipientId));

    // Check if session already exists
      try {
        const existingSessionKey = await getSessionKey(user.username, recipientId);
        if (existingSessionKey) {
          setSessions(prevSessions => {
          if (!prevSessions.has(recipientId)) {
            const newSessions = new Map(prevSessions);
            newSessions.set(recipientId, {
              sessionKey: existingSessionKey,
              messages: [],
              nonceTracker: new Set(),
              establishedAt: Date.now()
            });
            sessionsRef.current = newSessions;
            return newSessions;
          }
          return prevSessions;
          });
          setActiveRecipient(recipientId);
          activeRecipientRef.current = recipientId;
          setOpenChats(prev => {
            const newSet = new Set(prev);
            newSet.add(recipientId);
            return newSet;
          });
          setEstablishingSession(prev => {
          const newSet = new Set(prev);
          newSet.delete(recipientId);
          return newSet;
        });
        await loadPendingMessages(recipientId, existingSessionKey, false);
          return;
        }
      } catch (error) {
        // Continue to establish new session
      }

    try {
      // Get recipient's public key from server
      const { getUserPublicKey } = await import('../services/api.js');
      const recipientInfo = await getUserPublicKey(recipientId);
      
      if (!recipientInfo || !recipientInfo.publicKey) {
        throw new Error('Recipient not found or has no public key');
      }

      // Convert public key to Uint8Array and verify it's valid
      let recipientPublicKey;
      if (Array.isArray(recipientInfo.publicKey)) {
        recipientPublicKey = new Uint8Array(recipientInfo.publicKey);
      } else if (recipientInfo.publicKey instanceof Uint8Array) {
        recipientPublicKey = recipientInfo.publicKey;
      } else {
        throw new Error('Invalid public key format from server');
      }
      
      // Validate public key length (SPKI format for P-256 should be ~91 bytes)
      if (recipientPublicKey.length < 80 || recipientPublicKey.length > 100) {
        throw new Error(`Invalid public key length: ${recipientPublicKey.length} bytes. Expected ~91 bytes for ECDH P-256. The recipient may need to re-register.`);
      }

      // Check for pending key exchange
      let pendingExchange = null;
      try {
        const data = await getPendingKeyExchange(user.username, recipientId);
        if (data.success && data.ephemeralPublicKey) {
          pendingExchange = data;
        } else {
          await new Promise(resolve => setTimeout(resolve, 500));
          const dataAfterWait = await getPendingKeyExchange(user.username, recipientId);
          if (dataAfterWait.success && dataAfterWait.ephemeralPublicKey) {
            pendingExchange = dataAfterWait;
          }
        }
      } catch (error) {
        // Continue to initiate
      }

      let sessionKey;
      let sharedSecret;

      if (pendingExchange) {
        // Respond to key exchange
        const ourEphemeralKeyPair = await crypto.subtle.generateKey(
          { name: 'ECDH', namedCurve: 'P-256' },
          true,
          ['deriveBits', 'deriveKey']
        );

        const ourEphemeralPublicKey = await crypto.subtle.exportKey('spki', ourEphemeralKeyPair.publicKey);
        const ourEphemeralPublicKeyArray = new Uint8Array(ourEphemeralPublicKey);
        const ourEphemeralPrivateKey = await crypto.subtle.exportKey('pkcs8', ourEphemeralKeyPair.privateKey);

        let initiatorEphemeralPublicKey;
        if (Array.isArray(pendingExchange.ephemeralPublicKey)) {
          initiatorEphemeralPublicKey = new Uint8Array(pendingExchange.ephemeralPublicKey);
        } else if (pendingExchange.ephemeralPublicKey instanceof Uint8Array) {
          initiatorEphemeralPublicKey = new Uint8Array(pendingExchange.ephemeralPublicKey);
        } else {
          throw new Error('Invalid ephemeral public key format');
        }

        // Create response message
        const responseMessage = {
          version: '1.0',
          type: 'key-exchange-response',
          senderId: user.username,
          receiverId: recipientId,
          ephemeralPublicKey: Array.from(ourEphemeralPublicKeyArray),
          timestamp: Date.now(),
          nonce: Array.from(crypto.getRandomValues(new Uint8Array(16)))
        };

        // Sign the response
        const messageBytes = new TextEncoder().encode(JSON.stringify(responseMessage));
        const { signData } = await import('../crypto/signatures.js');
        const signature = await signData(messageBytes, keyPair.privateKey);

        // Send response to server
        await apiRespond(user.username, recipientId, {
          ephemeralPublicKey: Array.from(ourEphemeralPublicKeyArray),
          keyExchangeMessage: responseMessage,
          signature: Array.from(signature)
        });

        // Complete key exchange: compute shared secret using our ephemeral private * initiator's ephemeral public
        const completion = await completeKeyExchangeBidirectional(
          ourEphemeralPrivateKey,
          ourEphemeralPublicKeyArray,
          initiatorEphemeralPublicKey,
        user.username,
        recipientId
      );

        sessionKey = completion.sessionKey;
        sharedSecret = completion.sharedSecret;

        // Send completion to server
        await apiComplete(user.username, recipientId, {
          sessionKey: Array.from(sessionKey),
          salt: Array.from(completion.salt)
        });

      } else {
        // Initiate key exchange
        const ourEphemeralKeyPair = await crypto.subtle.generateKey(
          { name: 'ECDH', namedCurve: 'P-256' },
          true,
          ['deriveBits', 'deriveKey']
        );

        const ourEphemeralPublicKey = await crypto.subtle.exportKey('spki', ourEphemeralKeyPair.publicKey);
        const ourEphemeralPublicKeyArray = new Uint8Array(ourEphemeralPublicKey);
        const ourEphemeralPrivateKey = await crypto.subtle.exportKey('pkcs8', ourEphemeralKeyPair.privateKey);

        const initiationMessage = {
          version: '1.0',
          type: 'key-exchange-initiate',
          senderId: user.username,
          receiverId: recipientId,
          ephemeralPublicKey: Array.from(ourEphemeralPublicKeyArray),
          timestamp: Date.now(),
          nonce: Array.from(crypto.getRandomValues(new Uint8Array(16)))
        };

        const messageBytes = new TextEncoder().encode(JSON.stringify(initiationMessage));
        const { signData } = await import('../crypto/signatures.js');
        const signature = await signData(messageBytes, keyPair.privateKey);

      const ourEphemeralKeyPairForPolling = {
        privateKey: ourEphemeralPrivateKey,
        publicKey: ourEphemeralPublicKeyArray
      };
      
      await apiInitiate(user.username, recipientId, {
        ephemeralPublicKey: Array.from(ourEphemeralPublicKeyArray),
        keyExchangeMessage: initiationMessage,
        signature: Array.from(signature)
      });
      
        // Poll for response
        let responderEphemeralPublicKey = null;
        const maxWaitTime = 30000;
        const pollInterval = 1000;
        const startTime = Date.now();

        while (!responderEphemeralPublicKey && (Date.now() - startTime) < maxWaitTime) {
          try {
            const data = await getPendingKeyExchange(user.username, recipientId);
            if (data.success && data.ephemeralPublicKey) {
              if (Array.isArray(data.ephemeralPublicKey)) {
                responderEphemeralPublicKey = new Uint8Array(data.ephemeralPublicKey);
              } else if (data.ephemeralPublicKey instanceof Uint8Array) {
                responderEphemeralPublicKey = new Uint8Array(data.ephemeralPublicKey);
              }
              if (responderEphemeralPublicKey) break;
            }
          } catch (error) {
            // Continue polling
          }
          await new Promise(resolve => setTimeout(resolve, pollInterval));
        }

        if (!responderEphemeralPublicKey) {
          setEstablishingSession(prev => {
            const newSet = new Set(prev);
            newSet.delete(recipientId);
            return newSet;
          });
          throw new Error('Timeout waiting for key exchange response');
        }

        // Complete key exchange: compute shared secret using our ephemeral private * responder's ephemeral public
        // CRITICAL: Use the SAME ephemeral keys we sent, not regenerated ones
        const completion = await completeKeyExchangeBidirectional(
          ourEphemeralKeyPairForPolling.privateKey,
          ourEphemeralKeyPairForPolling.publicKey,
          responderEphemeralPublicKey,
          user.username,
          recipientId
        );

        sessionKey = completion.sessionKey;
        sharedSecret = completion.sharedSecret;

      // Send completion to server
        await apiComplete(user.username, recipientId, {
          sessionKey: Array.from(sessionKey),
        salt: Array.from(completion.salt)
      });
      }

      // Generate key confirmation
      const sessionId = `${user.username}-${recipientId}-${Date.now()}`;
      const confirmation = await generateKeyConfirmation(
        sharedSecret,
        sessionId,
        user.username,
        recipientId
      );

      // Send confirmation
      await apiConfirm(user.username, recipientId, confirmation);

      // Store session key
      await storeSessionKey(user.username, recipientId, sessionKey);
      
      // Reset sequence number tracking for this session (allows loading old messages)
      resetLastReceivedSequence(recipientId, user.username);
      
      // Clear any session key mismatch warnings for this recipient
      setSessionKeyMismatchUsers(prev => {
        const newSet = new Set(prev);
        newSet.delete(recipientId);
        return newSet;
      });
      
      // Clear undecryptable message count for this recipient
      setUndecryptableMessages(prev => {
        const newMap = new Map(prev);
        newMap.delete(recipientId);
        return newMap;
      });
      
      // Add session to state
      setSessions(prevSessions => {
          const newSessions = new Map(prevSessions);
        newSessions.set(recipientId, {
          sessionKey: sessionKey,
          messages: [],
          nonceTracker: new Set(),
          establishedAt: Date.now()
        });
        sessionsRef.current = newSessions;
        return newSessions;
      });
      setActiveRecipient(recipientId);
      activeRecipientRef.current = recipientId;
      setOpenChats(prev => {
        const newSet = new Set(prev);
        newSet.add(recipientId);
        return newSet;
      });
      
      setEstablishingSession(prev => {
        const newSet = new Set(prev);
        newSet.delete(recipientId);
        return newSet;
      });
      
      await loadPendingMessages(recipientId, sessionKey, false);
    } catch (error) {
      console.error('Failed to establish session:', error);
      // Remove from establishing set on error
      setEstablishingSession(prev => {
        const newSet = new Set(prev);
        newSet.delete(recipientId);
        return newSet;
      });
      alert('Failed to establish session: ' + error.message);
    }
  };

  // Disconnect from a session
  const disconnectSession = async (recipientId) => {
    try {
      // Delete session from IndexedDB
      await deleteSession(user.username, recipientId);
      
      // Remove from state and ref atomically
      setSessions(prevSessions => {
        const newSessions = new Map(prevSessions);
      newSessions.delete(recipientId);
        // Update ref immediately
        sessionsRef.current = newSessions;
        return newSessions;
      });
      
      // Clear from establishing set if present
      setEstablishingSession(prev => {
        const newSet = new Set(prev);
        newSet.delete(recipientId);
        return newSet;
      });
      
      // Remove from open chats
      setOpenChats(prev => {
        const newSet = new Set(prev);
        newSet.delete(recipientId);
        return newSet;
      });
      
      // Remove from minimized chats
      setMinimizedChats(prev => {
        const newSet = new Set(prev);
        newSet.delete(recipientId);
        return newSet;
      });
      
      // Clear session key mismatch warnings
      setSessionKeyMismatchUsers(prev => {
        const newSet = new Set(prev);
        newSet.delete(recipientId);
        return newSet;
      });
      
      // Clear undecryptable message count
      setUndecryptableMessages(prev => {
        const newMap = new Map(prev);
        newMap.delete(recipientId);
        return newMap;
      });
      
      // If this was the active session, switch to another or clear
      if (activeRecipient === recipientId) {
        const remainingSessions = Array.from(sessionsRef.current.keys());
        const newActiveRecipient = remainingSessions.length > 0 ? remainingSessions[0] : '';
        setActiveRecipient(newActiveRecipient);
        activeRecipientRef.current = newActiveRecipient;
      }
    } catch (error) {
      console.error('Failed to disconnect session:', error);
      alert('Failed to disconnect session: ' + error.message);
    }
  };

  // Load and display pending messages for a specific recipient
  const loadPendingMessages = async (recipientId, sessionKeyForRecipient) => {
    if (!sessionKeyForRecipient || !recipientId) return;
    
    try {
      const response = await getPendingMessages(user.username);
      
      if (response.messages && response.messages.length > 0) {
        const currentSessions = sessionsRef.current || sessions;
        let session = currentSessions.get(recipientId);
        
        if (!session) {
          const newSession = {
            sessionKey: sessionKeyForRecipient,
            messages: [],
            nonceTracker: new Set(),
            establishedAt: Date.now()
          };
          setSessions(prevSessions => {
            const newSessions = new Map(prevSessions);
            newSessions.set(recipientId, newSession);
            sessionsRef.current = newSessions;
            return newSessions;
          });
          session = newSession;
        }
        
        const updatedSession = {
          sessionKey: sessionKeyForRecipient,
          messages: [...session.messages],
          nonceTracker: new Set(session.nonceTracker),
          establishedAt: session.establishedAt || Date.now()
        };
        
        const sessionEstablishedAt = updatedSession.establishedAt;
        
        // Process each message
        for (const msg of response.messages) {
          if (msg.senderId !== recipientId) continue;
          
          const messageTimestamp = new Date(msg.timestamp).getTime();
          if (messageTimestamp < sessionEstablishedAt) continue;
          
          const alreadyDisplayed = updatedSession.messages.some(
            m => m.sequenceNumber === msg.sequenceNumber && m.sender === msg.senderId
          );
          const nonceStr = JSON.stringify(msg.nonce);
          const nonceAlreadyProcessed = updatedSession.nonceTracker.has(nonceStr);
          
          if (alreadyDisplayed || nonceAlreadyProcessed) {
            updatedSession.nonceTracker = new Set(updatedSession.nonceTracker).add(nonceStr);
            continue;
          }
          
          try {
            const encryptedMessage = {
              senderId: msg.senderId,
              receiverId: msg.receiverId,
              timestamp: msg.timestamp,
              sequenceNumber: msg.sequenceNumber,
              nonce: msg.nonce,
              iv: msg.iv,
              encryptedPayload: msg.encryptedPayload,
              authTag: msg.authTag
            };
            
            const lastSeq = getLastReceivedSequence(msg.senderId, msg.receiverId);
            const skipSequenceCheck = msg.sequenceNumber <= lastSeq;
            const newNonceTracker = new Set(updatedSession.nonceTracker);
            verifyMessage(encryptedMessage, newNonceTracker, true, skipSequenceCheck);
            updatedSession.nonceTracker = newNonceTracker;
            
            const decrypted = await decryptMessage(encryptedMessage, sessionKeyForRecipient);
            
            const newMessage = {
              sender: decrypted.senderId,
              receiver: decrypted.receiverId,
              message: decrypted.plaintext,
              timestamp: new Date(decrypted.timestamp),
              sequenceNumber: decrypted.sequenceNumber,
              encrypted: true
            };
            updatedSession.messages = [...updatedSession.messages, newMessage];
          } catch (error) {
            if (error.message.includes('Replay attack detected')) {
              updatedSession.nonceTracker = new Set(updatedSession.nonceTracker).add(nonceStr);
              continue;
            }
            // Skip decryption failures silently
              const messageTimestamp = new Date(msg.timestamp).getTime();
            if (messageTimestamp >= sessionEstablishedAt) {
                updatedSession.nonceTracker = new Set(updatedSession.nonceTracker).add(nonceStr);
              }
          }
        }
        
        setSessions(prevSessions => {
          const newSessions = new Map(prevSessions);
        newSessions.set(recipientId, updatedSession);
        sessionsRef.current = newSessions;
          return newSessions;
        });
      }
    } catch (error) {
      console.error('Failed to load messages:', error);
    }
  };

  const sendMessageHandler = async () => {
    const currentSession = getCurrentSession();
    if (!inputMessage || !activeRecipient || !currentSession) {
      alert('Please establish a session first');
      return;
    }

    try {
      // Encrypt message client-side (NO plaintext)
      const encrypted = await encryptMessage(
        inputMessage,
        currentSession.sessionKey,
        user.username,
        activeRecipient
      );

      // Send encrypted message (NO plaintext)
      await sendMessage(encrypted);
      // console.log('Message sent successfully'); // Reduced logging

      // Add to session's messages immediately for UI feedback
      // CRITICAL: Update both state and ref atomically
      setSessions(prevSessions => {
        const newSessions = new Map(prevSessions);
      const updatedSession = newSessions.get(activeRecipient);
      if (updatedSession) {
        const newMessage = {
        sender: user.username,
          receiver: activeRecipient,
        message: inputMessage,
        timestamp: new Date(),
          sequenceNumber: encrypted.sequenceNumber,
        encrypted: true
        };
          newSessions.set(activeRecipient, {
            ...updatedSession,
            messages: [...updatedSession.messages, newMessage]
          });
          // Update ref immediately
          sessionsRef.current = newSessions;
      } else {
        console.error('No session found for activeRecipient:', activeRecipient);
      }
        return newSessions;
      });
      // console.log('Message added to UI'); // Reduced logging

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
    const currentSession = getCurrentSession();
    if (!selectedFile || !activeRecipient || !currentSession) {
      alert('Please select a file and establish a session');
      return;
    }

    try {
      // Encrypt file client-side (NO plaintext)
      const encryptedFile = await encryptFile(selectedFile, currentSession.sessionKey);

      // Upload encrypted file (NO plaintext)
      await apiUploadFile({
        senderId: user.username,
        receiverId: activeRecipient,
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
      
      {/* Chat Cards Container */}
      <div style={{ 
        display: 'flex', 
        flexWrap: 'wrap', 
        gap: '15px', 
        padding: '15px',
        alignItems: 'flex-start',
        alignContent: 'flex-start'
      }}>
        {Array.from(sessions.keys()).map((recipientId) => {
          const session = sessions.get(recipientId);
          const isOpen = openChats.has(recipientId);
          const isMinimized = minimizedChats.has(recipientId);
          
          return (
              <div
                key={recipientId}
                style={{
                width: isMinimized ? '250px' : '350px',
                height: isMinimized ? 'auto' : '500px',
                backgroundColor: 'white',
                borderRadius: '8px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
                  display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
                transition: 'all 0.3s ease',
                border: `2px solid ${isOpen ? '#007bff' : '#dee2e6'}`
              }}
            >
              {/* Card Header */}
              <div
                  style={{
                  padding: '12px 15px',
                  backgroundColor: isOpen ? '#007bff' : '#f8f9fa',
                  color: isOpen ? 'white' : '#212529',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  cursor: 'pointer',
                  borderBottom: '1px solid #dee2e6'
                }}
                onClick={() => {
                  if (isMinimized) {
                    setMinimizedChats(prev => {
                      const newSet = new Set(prev);
                      newSet.delete(recipientId);
                      return newSet;
                    });
                  }
                  setOpenChats(prev => {
                    const newSet = new Set(prev);
                    if (isOpen) {
                      newSet.delete(recipientId);
              } else {
                      newSet.add(recipientId);
                    }
                    return newSet;
                  });
                  setActiveRecipient(recipientId);
                  activeRecipientRef.current = recipientId;
                  setOpenChats(prev => {
                    const newSet = new Set(prev);
                    newSet.add(recipientId);
                    return newSet;
                  });
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <div style={{ 
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    backgroundColor: session?.messages?.length > 0 ? '#28a745' : '#6c757d'
                  }} />
                  <strong>{recipientId}</strong>
                  {session?.messages?.length > 0 && (
                    <span style={{ 
                      fontSize: '12px', 
                      backgroundColor: isOpen ? 'rgba(255,255,255,0.2)' : '#007bff',
                      color: isOpen ? 'white' : 'white',
                      padding: '2px 6px',
                      borderRadius: '10px'
                    }}>
                      {session.messages.length}
                </span>
              )}
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setMinimizedChats(prev => {
                    const newSet = new Set(prev);
                      if (isMinimized) {
                        newSet.delete(recipientId);
                      } else {
                        newSet.add(recipientId);
                      }
                    return newSet;
                  });
                  }}
                  style={{
                    padding: '4px 8px',
                    fontSize: '12px',
                    backgroundColor: 'transparent',
                    color: isOpen ? 'white' : '#6c757d',
                    border: `1px solid ${isOpen ? 'rgba(255,255,255,0.3)' : '#dee2e6'}`,
                  borderRadius: '4px', 
                    cursor: 'pointer'
                  }}
                  title={isMinimized ? 'Restore' : 'Minimize'}
                >
                  {isMinimized ? '□' : '−'}
                </button>
              </div>

              {/* Card Content - Messages */}
              {!isMinimized && (
                <>
      <div style={{ 
                    flex: 1,
                    overflowY: 'auto',
                    padding: '15px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
        backgroundColor: '#f8f9fa'
      }}>
                    {session?.messages?.length === 0 ? (
                      <div style={{ 
                        padding: '20px', 
                        textAlign: 'center', 
                        color: '#666',
                        fontSize: '14px'
                      }}>
                        No messages yet
      </div>
                    ) : (
                      session?.messages?.map((msg, idx) => (
                        <div
                          key={idx}
          style={{
                            padding: '10px',
                            backgroundColor: msg.sender === user.username ? '#007bff' : 'white',
                            color: msg.sender === user.username ? 'white' : '#212529',
                            borderRadius: '8px',
                            alignSelf: msg.sender === user.username ? 'flex-end' : 'flex-start',
                            maxWidth: '80%',
                            boxShadow: '0 1px 2px rgba(0,0,0,0.1)'
                          }}
                        >
                          <div style={{ fontSize: '13px', marginBottom: '4px', opacity: 0.9 }}>
                            {msg.sender === user.username ? 'You' : msg.sender}
                    </div>
                          <div style={{ fontSize: '14px' }}>{msg.message}</div>
          <div style={{ 
                            fontSize: '11px', 
                            opacity: 0.7, 
                            marginTop: '4px',
                            textAlign: 'right'
                          }}>
                            {new Date(msg.timestamp).toLocaleTimeString()}
              </div>
          </div>
                      ))
        )}
      </div>

                  {/* Message Input */}
        <div style={{ 
                    padding: '10px',
                    borderTop: '1px solid #dee2e6',
                    display: 'flex',
                    gap: '8px',
                    backgroundColor: 'white'
                  }}>
                    <input
                      type="text"
                      value={activeRecipient === recipientId ? inputMessage : ''}
                      onChange={(e) => {
                        if (activeRecipient === recipientId) {
                          setInputMessage(e.target.value);
                        }
                      }}
                      onKeyPress={(e) => {
                        if (e.key === 'Enter' && activeRecipient === recipientId) {
                          sendMessageHandler();
                        }
                      }}
                      placeholder="Type a message..."
                style={{ 
                        flex: 1,
                        padding: '8px',
                        border: '1px solid #dee2e6',
                  borderRadius: '4px', 
                        fontSize: '14px'
                      }}
                      disabled={!session?.sessionKey}
                    />
              <button 
                      onClick={() => {
                        setActiveRecipient(recipientId);
                        activeRecipientRef.current = recipientId;
                        setOpenChats(prev => {
                          const newSet = new Set(prev);
                          newSet.add(recipientId);
                          return newSet;
                        });
                        sendMessageHandler();
                      }}
                      disabled={!session?.sessionKey || (activeRecipient !== recipientId && !inputMessage)}
                style={{ 
                        padding: '8px 16px',
                        backgroundColor: '#007bff',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                        fontSize: '14px'
                }}
              >
                      Send
              </button>
                              </div>
            </>
          )}
        </div>
          );
        })}
              </div>

      {/* Users List */}
      <div style={{ 
        padding: '20px',
        borderBottom: '1px solid #dee2e6',
        backgroundColor: '#f8f9fa',
        maxHeight: '200px',
        overflowY: 'auto'
      }}>
        <h3 style={{ marginBottom: '15px', fontSize: '16px', color: '#495057' }}>All Users</h3>
        {loadingUsers ? (
          <div style={{ textAlign: 'center', padding: '20px', color: '#666' }}>Loading users...</div>
        ) : availableUsers.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '20px', color: '#666' }}>No other users found</div>
        ) : (
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
            gap: '10px'
          }}>
            {availableUsers.map((u) => {
              const hasSession = sessions.has(u.username);
              const isEstablishing = establishingSession.has(u.username);
              
              return (
                <div
                  key={u.username}
                  onClick={() => startChatWithUser(u.username)}
                  style={{
                    padding: '12px 15px',
                    backgroundColor: hasSession ? '#d4edda' : 'white',
                    border: `2px solid ${hasSession ? '#28a745' : '#dee2e6'}`,
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between'
                  }}
                  onMouseEnter={(e) => {
                    if (!isEstablishing) {
                      e.currentTarget.style.backgroundColor = hasSession ? '#c3e6cb' : '#e9ecef';
                      e.currentTarget.style.transform = 'translateY(-2px)';
                      e.currentTarget.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = hasSession ? '#d4edda' : 'white';
                    e.currentTarget.style.transform = 'translateY(0)';
                    e.currentTarget.style.boxShadow = 'none';
                  }}
                >
                  <div>
                    <div style={{ fontWeight: '600', color: '#212529', fontSize: '14px' }}>
                      {u.username}
                    </div>
                    {u.name && (
                      <div style={{ fontSize: '12px', color: '#6c757d', marginTop: '2px' }}>
                        {u.name}
                      </div>
                    )}
                  </div>
                  <div style={{ fontSize: '12px', color: hasSession ? '#28a745' : '#6c757d' }}>
                    {isEstablishing ? '⏳' : hasSession ? '✓' : '○'}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {activeRecipient && establishingSession.has(activeRecipient) && (
        <div style={{ 
          padding: '15px', 
          backgroundColor: '#fff3cd', 
          border: '1px solid #ffc107', 
          borderRadius: '4px',
          marginBottom: '10px',
          margin: '15px'
        }}>
          <strong>⏳ Establishing secure session with {activeRecipient}...</strong>
          <p style={{ marginTop: '8px', fontSize: '14px', color: '#856404' }}>
            Waiting for {activeRecipient} to start a chat with you.
          </p>
          </div>
      )}

      {/* New Chat Button */}
      {sessions.size === 0 && (
      <div style={{ 
          padding: '40px', 
          textAlign: 'center', 
          color: '#666' 
        }}>
          <p style={{ fontSize: '18px', marginBottom: '20px' }}>
            No active chats. Start a new conversation!
          </p>
          </div>
        )}
    </div>
  );
}

export default Chat;
