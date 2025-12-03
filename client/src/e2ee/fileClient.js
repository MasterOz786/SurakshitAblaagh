/**
 * Client-Side File Encryption/Decryption
 * Files encrypted before upload - all client-side
 */

import { encryptAESGCM, decryptAESGCM, generateIV } from '../crypto/webCrypto.js';

const CHUNK_SIZE = 1024 * 1024; // 1MB chunks

// Encrypt file client-side before upload
export async function encryptFile(file, sessionKey) {
  const fileBuffer = await file.arrayBuffer();
  const fileBytes = new Uint8Array(fileBuffer);
  
  // Split into chunks
  const chunks = [];
  for (let i = 0; i < fileBytes.length; i += CHUNK_SIZE) {
    chunks.push(fileBytes.slice(i, i + CHUNK_SIZE));
  }
  
  // Encrypt each chunk with AES-256-GCM
  const encryptedChunks = [];
  for (let i = 0; i < chunks.length; i++) {
    const iv = generateIV(); // Fresh IV per chunk
    const encrypted = await encryptAESGCM(chunks[i], sessionKey, iv);
    
    encryptedChunks.push({
      chunkIndex: i,
      iv: Array.from(iv),
      encryptedData: Array.from(encrypted.encrypted),
      authTag: Array.from(encrypted.authTag)
    });
  }
  
  return {
    fileName: file.name,
    fileSize: file.size,
    mimeType: file.type,
    totalChunks: chunks.length,
    encryptedChunks: encryptedChunks
  };
}

// Decrypt file client-side after download
export async function decryptFile(encryptedFileData, sessionKey) {
  const { encryptedChunks } = encryptedFileData;
  
  // Decrypt each chunk
  const decryptedChunks = [];
  for (const chunk of encryptedChunks) {
    const encryptedData = new Uint8Array(chunk.encryptedData);
    const iv = new Uint8Array(chunk.iv);
    const authTag = new Uint8Array(chunk.authTag);
    
    const decrypted = await decryptAESGCM(encryptedData, sessionKey, iv, authTag);
    decryptedChunks.push(decrypted);
  }
  
  // Reassemble file
  const totalSize = decryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const fileBytes = new Uint8Array(totalSize);
  let offset = 0;
  for (const chunk of decryptedChunks) {
    fileBytes.set(chunk, offset);
    offset += chunk.length;
  }
  
  return fileBytes;
}

