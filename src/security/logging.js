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
  MESSAGE_SENT: 'message_sent',
  MESSAGE_RECEIVED: 'message_received',
  FILE_UPLOADED: 'file_uploaded',
  FILE_DOWNLOADED: 'file_downloaded',
  ATTACK_DETECTED: 'attack_detected',
  AUTHENTICATION_FAILED: 'authentication_failed',
  REPLAY_DETECTED: 'replay_detected',
  MITM_DETECTED: 'mitm_detected',
  SESSION_ESTABLISHED: 'session_established',
  SESSION_TERMINATED: 'session_terminated'
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
    [SecurityEventType.REPLAY_DETECTED]: 'HIGH',
    [SecurityEventType.AUTHENTICATION_FAILED]: 'HIGH',
    [SecurityEventType.KEY_EXCHANGE]: 'MEDIUM',
    [SecurityEventType.SESSION_ESTABLISHED]: 'MEDIUM',
    [SecurityEventType.MESSAGE_SENT]: 'LOW',
    [SecurityEventType.MESSAGE_RECEIVED]: 'LOW',
    [SecurityEventType.FILE_UPLOADED]: 'LOW',
    [SecurityEventType.FILE_DOWNLOADED]: 'LOW'
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

// Analyze security events
export function analyzeSecurityEvents(events) {
  const analysis = {
    totalEvents: events.length,
    attackCount: 0,
    failedAuthCount: 0,
    keyExchanges: 0,
    messagesSent: 0,
    messagesReceived: 0
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
      case SecurityEventType.KEY_EXCHANGE:
        analysis.keyExchanges++;
        break;
      case SecurityEventType.MESSAGE_SENT:
        analysis.messagesSent++;
        break;
      case SecurityEventType.MESSAGE_RECEIVED:
        analysis.messagesReceived++;
        break;
    }
  }

  return analysis;
}

