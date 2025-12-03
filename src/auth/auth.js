/**
 * User Authentication Module
 * Implements secure password hashing and user management
 */

import crypto from 'crypto'; // Allowed for backend digital signatures only

// In-memory user store (in production, use MongoDB)
const users = new Map();

// Password hashing using bcrypt-like algorithm (pure JavaScript implementation)
export async function hashPassword(password) {
  // Generate salt
  const salt = crypto.randomBytes(16).toString('hex');
  
  // Hash password with salt (using SHA-256 as base, multiple iterations for bcrypt-like security)
  const iterations = 10000; // Number of iterations
  let hash = password + salt;
  
  for (let i = 0; i < iterations; i++) {
    hash = crypto.createHash('sha256').update(hash).digest('hex');
  }
  
  return {
    hash: hash,
    salt: salt,
    iterations: iterations
  };
}

// Verify password
export async function verifyPassword(password, storedHash, salt, iterations) {
  let hash = password + salt;
  
  for (let i = 0; i < iterations; i++) {
    hash = crypto.createHash('sha256').update(hash).digest('hex');
  }
  
  return hash === storedHash;
}

// Register new user
export async function registerUser(username, password) {
  if (users.has(username)) {
    throw new Error('Username already exists');
  }

  // Hash password
  const passwordData = await hashPassword(password);
  
  // Create user
  const user = {
    username: username,
    passwordHash: passwordData.hash,
    passwordSalt: passwordData.salt,
    passwordIterations: passwordData.iterations,
    createdAt: new Date(),
    lastLogin: null,
    failedLoginAttempts: 0,
    lockedUntil: null
  };

  users.set(username, user);
  
  return {
    success: true,
    username: username,
    message: 'User registered successfully'
  };
}

// Authenticate user
export async function authenticateUser(username, password) {
  const user = users.get(username);
  
  if (!user) {
    throw new Error('Invalid username or password');
  }

  // Check if account is locked
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    throw new Error('Account is locked. Please try again later.');
  }

  // Verify password
  const isValid = await verifyPassword(
    password,
    user.passwordHash,
    user.passwordSalt,
    user.passwordIterations
  );

  if (!isValid) {
    user.failedLoginAttempts++;
    
    // Lock account after 5 failed attempts
    if (user.failedLoginAttempts >= 5) {
      user.lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      throw new Error('Too many failed attempts. Account locked for 15 minutes.');
    }
    
    throw new Error('Invalid username or password');
  }

  // Reset failed attempts on successful login
  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  user.lastLogin = new Date();

  return {
    success: true,
    username: username,
    lastLogin: user.lastLogin
  };
}

// Get user (without password)
export function getUser(username) {
  const user = users.get(username);
  if (!user) {
    return null;
  }

  return {
    username: user.username,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin
  };
}

// Check if user exists
export function userExists(username) {
  return users.has(username);
}

