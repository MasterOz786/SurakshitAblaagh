/**
 * User Authentication Module
 * Implements secure password hashing and user management
 * Uses MongoDB for persistent storage
 */

import crypto from 'crypto';
import { 
  storeUser, 
  getUserFromDB, 
  updateUser as updateUserInDB, 
  userExistsInDB,
  getDB 
} from '../db/mongodb.js';

// In-memory fallback cache (for performance, MongoDB is source of truth)
const userCache = new Map();

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
  // Check if user exists (MongoDB first, then cache)
  const db = getDB();
  if (db) {
    const exists = await userExistsInDB(username);
    if (exists) {
      throw new Error('Username already exists');
    }
  } else if (userCache.has(username)) {
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

  // Store in MongoDB if available
  if (db) {
    await storeUser(user);
  } else {
    // Fallback to in-memory
    userCache.set(username, user);
  }
  
  return {
    success: true,
    username: username,
    message: 'User registered successfully'
  };
}

// Authenticate user
export async function authenticateUser(username, password) {
  // Get user from MongoDB or cache
  const db = getDB();
  let user = null;
  
  if (db) {
    user = await getUserFromDB(username);
    // Update cache
    if (user) {
      userCache.set(username, user);
    }
  } else {
    user = userCache.get(username);
  }
  
  if (!user) {
    throw new Error('Invalid username or password');
  }

  // Check if account is locked
  if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
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
    user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
    
    // Lock account after 5 failed attempts
    if (user.failedLoginAttempts >= 5) {
      user.lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      
      // Update in MongoDB
      if (db) {
        await updateUserInDB(username, {
          failedLoginAttempts: user.failedLoginAttempts,
          lockedUntil: user.lockedUntil
        });
      }
      
      throw new Error('Too many failed attempts. Account locked for 15 minutes.');
    }
    
    // Update failed attempts
    if (db) {
      await updateUserInDB(username, {
        failedLoginAttempts: user.failedLoginAttempts
      });
    } else {
      userCache.set(username, user);
    }
    
    throw new Error('Invalid username or password');
  }

  // Reset failed attempts on successful login
  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  user.lastLogin = new Date();

  // Update in MongoDB
  if (db) {
    await updateUserInDB(username, {
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastLogin: user.lastLogin
    });
  } else {
    userCache.set(username, user);
  }

  return {
    success: true,
    username: username,
    lastLogin: user.lastLogin
  };
}

// Get user (without password)
export async function getUser(username) {
  const db = getDB();
  let user = null;
  
  if (db) {
    user = await getUserFromDB(username);
    if (user) {
      userCache.set(username, user);
    }
  } else {
    user = userCache.get(username);
  }
  
  if (!user) {
    return null;
  }

  return {
    username: user.username,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin,
    email: user.email,
    name: user.name,
    oauthProvider: user.oauthProvider
  };
}

// Check if user exists
export async function userExists(username) {
  const db = getDB();
  
  if (db) {
    return await userExistsInDB(username);
  }
  
  return userCache.has(username);
}

// Update user (for OAuth and other updates)
export async function updateUser(username, updateData) {
  const db = getDB();
  
  if (db) {
    const updated = await updateUserInDB(username, updateData);
    if (updated) {
      // Refresh cache
      const user = await getUserFromDB(username);
      if (user) {
        userCache.set(username, user);
      }
    }
    return updated;
  } else {
    const user = userCache.get(username);
    if (user) {
      Object.assign(user, updateData);
      userCache.set(username, user);
      return true;
    }
    return false;
  }
}

