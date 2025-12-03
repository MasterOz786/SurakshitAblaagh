/**
 * Threat Modeling and Security Analysis
 */

// Threat categories
export const ThreatCategory = {
  MITM: 'man_in_the_middle',
  REPLAY: 'replay_attack',
  EAVESDROPPING: 'eavesdropping',
  KEY_COMPROMISE: 'key_compromise',
  DENIAL_OF_SERVICE: 'denial_of_service',
  UNAUTHORIZED_ACCESS: 'unauthorized_access'
};

// Threat model
export const threatModel = {
  threats: [
    {
      id: 'T1',
      category: ThreatCategory.MITM,
      description: 'Attacker intercepts communication and impersonates parties',
      likelihood: 'MEDIUM',
      impact: 'HIGH',
      mitigations: [
        'Certificate pinning',
        'Public key verification',
        'Out-of-band key verification',
        'TLS/HTTPS transport encryption'
      ],
      status: 'MITIGATED'
    },
    {
      id: 'T2',
      category: ThreatCategory.REPLAY,
      description: 'Attacker captures and replays legitimate messages',
      likelihood: 'HIGH',
      impact: 'MEDIUM',
      mitigations: [
        'Nonce tracking',
        'Timestamp validation',
        'Message sequence numbers',
        'One-time message IDs'
      ],
      status: 'MITIGATED'
    },
    {
      id: 'T3',
      category: ThreatCategory.EAVESDROPPING,
      description: 'Attacker intercepts encrypted messages',
      likelihood: 'HIGH',
      impact: 'LOW',
      mitigations: [
        'End-to-end encryption (AES-GCM)',
        'Perfect forward secrecy',
        'Session key rotation',
        'Strong key derivation (HKDF)'
      ],
      status: 'MITIGATED'
    },
    {
      id: 'T4',
      category: ThreatCategory.KEY_COMPROMISE,
      description: 'Attacker compromises encryption keys',
      likelihood: 'LOW',
      impact: 'CRITICAL',
      mitigations: [
        'Key rotation',
        'Perfect forward secrecy',
        'Secure key storage',
        'Key escrow prevention'
      ],
      status: 'MITIGATED'
    },
    {
      id: 'T5',
      category: ThreatCategory.DENIAL_OF_SERVICE,
      description: 'Attacker floods server with requests',
      likelihood: 'MEDIUM',
      impact: 'MEDIUM',
      mitigations: [
        'Rate limiting',
        'Request validation',
        'Resource quotas',
        'Connection limits'
      ],
      status: 'PARTIALLY_MITIGATED'
    },
    {
      id: 'T6',
      category: ThreatCategory.UNAUTHORIZED_ACCESS,
      description: 'Unauthorized user accesses system',
      likelihood: 'MEDIUM',
      impact: 'HIGH',
      mitigations: [
        'User authentication',
        'Session management',
        'Access control',
        'Audit logging'
      ],
      status: 'MITIGATED'
    }
  ]
};

// Security analysis
export function analyzeSecurity() {
  const analysis = {
    totalThreats: threatModel.threats.length,
    mitigated: 0,
    partiallyMitigated: 0,
    unmitigated: 0,
    highImpact: 0,
    criticalThreats: []
  };

  for (const threat of threatModel.threats) {
    if (threat.status === 'MITIGATED') {
      analysis.mitigated++;
    } else if (threat.status === 'PARTIALLY_MITIGATED') {
      analysis.partiallyMitigated++;
    } else {
      analysis.unmitigated++;
    }

    if (threat.impact === 'CRITICAL' || threat.impact === 'HIGH') {
      analysis.highImpact++;
      if (threat.status !== 'MITIGATED') {
        analysis.criticalThreats.push(threat);
      }
    }
  }

  return analysis;
}

// Get threat by category
export function getThreatsByCategory(category) {
  return threatModel.threats.filter(t => t.category === category);
}

// Get mitigation strategies
export function getMitigationStrategies() {
  const strategies = new Set();
  
  for (const threat of threatModel.threats) {
    for (const mitigation of threat.mitigations) {
      strategies.add(mitigation);
    }
  }

  return Array.from(strategies);
}

// Security score calculation
export function calculateSecurityScore() {
  const analysis = analyzeSecurity();
  const total = analysis.totalThreats;
  const mitigated = analysis.mitigated;
  const partial = analysis.partiallyMitigated;
  
  // Score: 100% for mitigated, 50% for partially mitigated
  const score = ((mitigated * 100 + partial * 50) / total).toFixed(2);
  
  return {
    score: parseFloat(score),
    grade: getSecurityGrade(parseFloat(score)),
    analysis: analysis
  };
}

function getSecurityGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// Generate security report
export function generateSecurityReport() {
  const analysis = analyzeSecurity();
  const score = calculateSecurityScore();
  
  return {
    timestamp: new Date().toISOString(),
    securityScore: score,
    threatAnalysis: analysis,
    threats: threatModel.threats,
    recommendations: generateRecommendations(analysis)
  };
}

function generateRecommendations(analysis) {
  const recommendations = [];

  if (analysis.unmitigated > 0) {
    recommendations.push({
      priority: 'HIGH',
      action: 'Address unmitigated threats immediately'
    });
  }

  if (analysis.partiallyMitigated > 0) {
    recommendations.push({
      priority: 'MEDIUM',
      action: 'Strengthen mitigations for partially mitigated threats'
    });
  }

  if (analysis.criticalThreats.length > 0) {
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Review and strengthen mitigations for critical threats'
    });
  }

  return recommendations;
}

