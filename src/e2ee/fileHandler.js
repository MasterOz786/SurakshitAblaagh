/**
 * E2EE File Encryption/Decryption
 * Pure JavaScript implementation
 */

import { encryptAESGCM, decryptAESGCM, generateIV, deriveKey, generateSalt } from './crypto.js';

// Chunk size for file encryption (1MB chunks)
const CHUNK_SIZE = 1024 * 1024;

// Encrypt a file (chunked)
export function encryptFile(fileData, sessionKey, fileName) {
  const chunks = [];
  const totalChunks = Math.ceil(fileData.length / CHUNK_SIZE);
  
  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, fileData.length);
    const chunk = fileData.slice(start, end);
    
    // Generate IV for this chunk
    const iv = generateIV();
    
    // Encrypt chunk
    const encrypted = encryptAESGCM(chunk, sessionKey, iv);
    
    chunks.push({
      chunkIndex: i,
      totalChunks: totalChunks,
      iv: Array.from(iv),
      encryptedData: Array.from(encrypted.encrypted),
      authTag: Array.from(encrypted.authTag)
    });
  }
  
  return {
    fileName: fileName,
    fileSize: fileData.length,
    chunks: chunks,
    metadata: {
      originalSize: fileData.length,
      chunkSize: CHUNK_SIZE,
      encryptedAt: Date.now()
    }
  };
}

// Decrypt a file
export function decryptFile(encryptedFile, sessionKey) {
  // Sort chunks by index
  const sortedChunks = encryptedFile.chunks.sort((a, b) => a.chunkIndex - b.chunkIndex);
  
  // Verify all chunks are present
  if (sortedChunks.length !== encryptedFile.chunks[0].totalChunks) {
    throw new Error('Missing file chunks');
  }
  
  // Decrypt each chunk
  const decryptedChunks = [];
  for (const chunk of sortedChunks) {
    const encryptedData = new Uint8Array(chunk.encryptedData);
    const iv = new Uint8Array(chunk.iv);
    const authTag = new Uint8Array(chunk.authTag);
    
    const decrypted = decryptAESGCM(encryptedData, sessionKey, iv, authTag);
    decryptedChunks.push(decrypted);
  }
  
  // Combine chunks
  const totalLength = decryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  
  for (const chunk of decryptedChunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  
  return {
    fileName: encryptedFile.fileName,
    data: result,
    size: result.length
  };
}

