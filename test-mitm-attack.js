/**
 * MITM Attack Test - Requirement 7
 * Comprehensive demonstration of MITM attack on Diffie-Hellman key exchange
 * 
 * This script demonstrates:
 * 1. How MITM successfully breaks DH WITHOUT signatures
 * 2. How digital signatures PREVENT MITM in the final system
 * 
 * Run with: node test-mitm-attack.js
 */

import './src/attacks/mitm-attacker.js';
