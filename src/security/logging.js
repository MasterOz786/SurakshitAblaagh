/**
 * Security Logging Module
 * Logs all security-relevant events
 */

import winston from 'winston';

// Create logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'security.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Security event types
export const SecurityEventType = {
  KEY_EXCHANGE: 'key_exchange',
  KEY_EXCHANGE_FAILED: 'key_exchange_failed',
  MESSAGE_SENT: 'message_sent',
  MESSAGE_RECEIVED: 'message_received',
  MESSAGE_DECRYPTION_FAILED: 'message_decryption_failed',
  FILE_UPLOADED: 'file_uploaded',
  FILE_DOWNLOADED: 'file_downloaded',
  ATTACK_DETECTED: 'attack_detected',
  AUTHENTICATION_ATTEMPT: 'authentication_attempt',
  AUTHENTICATION_FAILED: 'authentication_failed',
  AUTHENTICATION_SUCCESS: 'authentication_success',
  REPLAY_DETECTED: 'replay_detected',
  MITM_DETECTED: 'mitm_detected',
  INVALID_SIGNATURE: 'invalid_signature',
  SESSION_ESTABLISHED: 'session_established',
  SESSION_TERMINATED: 'session_terminated',
  METADATA_ACCESS: 'metadata_access'
};

// Log security event
export function logSecurityEvent(eventType, details) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    eventType: eventType,
    details: details,
    severity: getSeverity(eventType)
  };

  logger.info('Security Event', logEntry);
  
  return logEntry;
}

// Get severity level for event type
function getSeverity(eventType) {
  const severityMap = {
    [SecurityEventType.ATTACK_DETECTED]: 'CRITICAL',
    [SecurityEventType.MITM_DETECTED]: 'CRITICAL',
    [SecurityEventType.INVALID_SIGNATURE]: 'CRITICAL',
    [SecurityEventType.REPLAY_DETECTED]: 'HIGH',
    [SecurityEventType.AUTHENTICATION_FAILED]: 'HIGH',
    [SecurityEventType.MESSAGE_DECRYPTION_FAILED]: 'HIGH',
    [SecurityEventType.KEY_EXCHANGE_FAILED]: 'HIGH',
    [SecurityEventType.KEY_EXCHANGE]: 'MEDIUM',
    [SecurityEventType.SESSION_ESTABLISHED]: 'MEDIUM',
    [SecurityEventType.AUTHENTICATION_ATTEMPT]: 'MEDIUM',
    [SecurityEventType.AUTHENTICATION_SUCCESS]: 'MEDIUM',
    [SecurityEventType.MESSAGE_SENT]: 'LOW',
    [SecurityEventType.MESSAGE_RECEIVED]: 'LOW',
    [SecurityEventType.FILE_UPLOADED]: 'LOW',
    [SecurityEventType.FILE_DOWNLOADED]: 'LOW',
    [SecurityEventType.METADATA_ACCESS]: 'LOW'
  };

  return severityMap[eventType] || 'LOW';
}

// Log key exchange
export function logKeyExchange(senderId, receiverId, success) {
  return logSecurityEvent(SecurityEventType.KEY_EXCHANGE, {
    senderId,
    receiverId,
    success,
    timestamp: Date.now()
  });
}

// Log attack detection
export function logAttackDetected(attackType, details) {
  return logSecurityEvent(SecurityEventType.ATTACK_DETECTED, {
    attackType,
    ...details,
    timestamp: Date.now()
  });
}

// Log message event
export function logMessageEvent(eventType, senderId, receiverId, messageId) {
  return logSecurityEvent(eventType, {
    senderId,
    receiverId,
    messageId,
    timestamp: Date.now()
  });
}

// Log file event
export function logFileEvent(eventType, userId, fileName, fileSize) {
  return logSecurityEvent(eventType, {
    userId,
    fileName,
    fileSize,
    timestamp: Date.now()
  });
}

// Get security audit log
export function getAuditLog(startTime, endTime) {
  // In production, query from database
  // For now, return empty array
  return [];
}

// Log authentication attempt
export function logAuthenticationAttempt(username, success) {
  return logSecurityEvent(
    success ? SecurityEventType.AUTHENTICATION_SUCCESS : SecurityEventType.AUTHENTICATION_FAILED,
    {
      username,
      timestamp: Date.now()
    }
  );
}

// Log failed message decryption
export function logDecryptionFailure(receiverId, senderId, error) {
  return logSecurityEvent(SecurityEventType.MESSAGE_DECRYPTION_FAILED, {
    receiverId,
    senderId,
    error: error.message || error,
    timestamp: Date.now()
  });
}

// Log invalid signature
export function logInvalidSignature(userId, context, details) {
  return logSecurityEvent(SecurityEventType.INVALID_SIGNATURE, {
    userId,
    context, // e.g., 'key_exchange', 'message'
    ...details,
    timestamp: Date.now()
  });
}

// Log metadata access
export function logMetadataAccess(userId, accessType, resourceId) {
  return logSecurityEvent(SecurityEventType.METADATA_ACCESS, {
    userId,
    accessType, // e.g., 'message_query', 'file_query', 'session_query'
    resourceId,
    timestamp: Date.now()
  });
}

// Analyze security events
export function analyzeSecurityEvents(events) {
  const analysis = {
    totalEvents: events.length,
    attackCount: 0,
    failedAuthCount: 0,
    failedDecryptions: 0,
    invalidSignatures: 0,
    keyExchanges: 0,
    keyExchangeFailures: 0,
    messagesSent: 0,
    messagesReceived: 0,
    metadataAccesses: 0
  };

  for (const event of events) {
    switch (event.eventType) {
      case SecurityEventType.ATTACK_DETECTED:
      case SecurityEventType.MITM_DETECTED:
      case SecurityEventType.REPLAY_DETECTED:
        analysis.attackCount++;
        break;
      case SecurityEventType.AUTHENTICATION_FAILED:
        analysis.failedAuthCount++;
        break;
      case SecurityEventType.MESSAGE_DECRYPTION_FAILED:
        analysis.failedDecryptions++;
        break;
      case SecurityEventType.INVALID_SIGNATURE:
        analysis.invalidSignatures++;
        break;
      case SecurityEventType.KEY_EXCHANGE:
        analysis.keyExchanges++;
        break;
      case SecurityEventType.KEY_EXCHANGE_FAILED:
        analysis.keyExchangeFailures++;
        break;
      case SecurityEventType.MESSAGE_SENT:
        analysis.messagesSent++;
        break;
      case SecurityEventType.MESSAGE_RECEIVED:
        analysis.messagesReceived++;
        break;
      case SecurityEventType.METADATA_ACCESS:
        analysis.metadataAccesses++;
        break;
    }
  }

  return analysis;
}

