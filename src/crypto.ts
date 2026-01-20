/**
 * Cryptographic utilities for session key management
 * 
 * Uses industry-standard audited libraries:
 * - @noble/curves: secp256k1 elliptic curve operations (audited by Cure53)
 * - @noble/hashes: SHA-256, PBKDF2, and other hash functions
 * - @scure/bip39: Mnemonic phrase generation (BIP-39)
 * - @scure/bip32: HD key derivation (BIP-32)
 * - Web Crypto API: AES-GCM encryption for key storage
 * 
 * Security features:
 * - Constant-time operations to prevent timing attacks
 * - Cryptographically secure random number generation
 * - Memory-safe operations where possible
 * - No vulnerable dependencies
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { wordlist } from '@scure/bip39/wordlists/english';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTANTS
 * ═══════════════════════════════════════════════════════════════════════════ */

const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_LENGTH = 256;

/* ═══════════════════════════════════════════════════════════════════════════
 * PRIVATE KEY GENERATION (using @noble/curves)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Generates a cryptographically secure random private key using @noble/curves
 * This is the most secure method - uses crypto.getRandomValues() internally
 * 
 * @returns Private key as hex string with 0x prefix
 */
export function generatePrivateKey(): string {
  // Generate 32 bytes of cryptographically secure random data
  const privateKeyBytes = randomBytes(32);
  
  // Validate it's a valid secp256k1 private key (must be < curve order)
  // The @noble library will throw if invalid, but we regenerate to be safe
  if (!isValidPrivateKey(privateKeyBytes)) {
    // Extremely rare case - regenerate
    return generatePrivateKey();
  }
  
  return '0x' + bytesToHex(privateKeyBytes);
}

/**
 * Validates that a byte array is a valid secp256k1 private key
 */
export function isValidPrivateKey(privateKey: Uint8Array | string): boolean {
  try {
    const bytes = typeof privateKey === 'string' 
      ? hexToBytes(privateKey.replace('0x', ''))
      : privateKey;
    
    // Must be 32 bytes and less than curve order
    if (bytes.length !== 32) return false;
    
    // Validate by attempting to get public key
    secp256k1.getPublicKey(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * Derives the public key from a private key
 * 
 * @param privateKey - Private key as hex string (with or without 0x prefix)
 * @returns Uncompressed public key as hex string with 0x prefix
 */
export function getPublicKey(privateKey: string): string {
  const privateKeyBytes = hexToBytes(privateKey.replace('0x', ''));
  const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes, false); // uncompressed
  return '0x' + bytesToHex(publicKeyBytes);
}

/**
 * Derives the Ethereum address from a private key
 * 
 * @param privateKey - Private key as hex string
 * @returns Ethereum address with 0x prefix and checksum
 */
export function getAddress(privateKey: string): string {
  const privateKeyBytes = hexToBytes(privateKey.replace('0x', ''));
  const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes, false);
  
  // Remove the 04 prefix (uncompressed marker) and hash with keccak256
  const publicKeyWithoutPrefix = publicKeyBytes.slice(1);
  const hash = keccak_256(publicKeyWithoutPrefix);
  
  // Take last 20 bytes as address
  const addressBytes = hash.slice(-20);
  const address = '0x' + bytesToHex(addressBytes);
  
  // Apply EIP-55 checksum
  return toChecksumAddress(address);
}

/**
 * Applies EIP-55 checksum to an address
 */
export function toChecksumAddress(address: string): string {
  const addr = address.toLowerCase().replace('0x', '');
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(addr)));
  
  let checksumAddress = '0x';
  for (let i = 0; i < addr.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      checksumAddress += addr[i].toUpperCase();
    } else {
      checksumAddress += addr[i];
    }
  }
  
  return checksumAddress;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MNEMONIC-BASED KEY GENERATION (using @scure/bip39 + @scure/bip32)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Generates a new mnemonic phrase (12 or 24 words)
 * Uses @scure/bip39 which is audited and constant-time
 * 
 * @param strength - 128 for 12 words, 256 for 24 words
 * @returns BIP-39 mnemonic phrase
 */
export function generateMnemonicPhrase(strength: 128 | 256 = 128): string {
  return generateMnemonic(wordlist, strength);
}

/**
 * Validates a mnemonic phrase
 */
export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, wordlist);
}

/**
 * Derives a private key from a mnemonic using BIP-32/BIP-44 path
 * Default path is Ethereum: m/44'/60'/0'/0/0
 * 
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param path - Derivation path (default: Ethereum standard)
 * @param passphrase - Optional BIP-39 passphrase
 * @returns Private key as hex string with 0x prefix
 */
export function deriveKeyFromMnemonic(
  mnemonic: string,
  path: string = "m/44'/60'/0'/0/0",
  passphrase: string = ''
): string {
  if (!isValidMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase');
  }
  
  // Convert mnemonic to seed
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  
  // Derive HD key
  const hdKey = HDKey.fromMasterSeed(seed);
  const derived = hdKey.derive(path);
  
  if (!derived.privateKey) {
    throw new Error('Failed to derive private key');
  }
  
  return '0x' + bytesToHex(derived.privateKey);
}

/**
 * Generates a new wallet with mnemonic
 * 
 * @returns Object containing mnemonic, private key, and address
 */
export function generateWalletWithMnemonic(): {
  mnemonic: string;
  privateKey: string;
  address: string;
} {
  const mnemonic = generateMnemonicPhrase();
  const privateKey = deriveKeyFromMnemonic(mnemonic);
  const address = getAddress(privateKey);
  
  return { mnemonic, privateKey, address };
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SIGNING (using @noble/curves)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Signs a message hash with a private key
 * Uses deterministic k (RFC 6979) for security
 * 
 * @param messageHash - 32-byte message hash
 * @param privateKey - Private key as hex string
 * @returns Signature with r, s, v components
 */
export function signHash(
  messageHash: Uint8Array | string,
  privateKey: string
): { r: string; s: string; v: number; signature: string } {
  const hashBytes = typeof messageHash === 'string' 
    ? hexToBytes(messageHash.replace('0x', ''))
    : messageHash;
  const privateKeyBytes = hexToBytes(privateKey.replace('0x', ''));
  
  // Sign with recovery bit
  const signature = secp256k1.sign(hashBytes, privateKeyBytes);
  
  const r = signature.r.toString(16).padStart(64, '0');
  const s = signature.s.toString(16).padStart(64, '0');
  const v = signature.recovery + 27; // Ethereum uses 27/28
  
  // Compact signature format (r + s + v)
  const fullSig = '0x' + r + s + v.toString(16);
  
  return { r: '0x' + r, s: '0x' + s, v, signature: fullSig };
}

/**
 * Hashes a message with the Ethereum prefix
 * 
 * @param message - Message to hash
 * @returns Prefixed message hash
 */
export function hashMessage(message: string): Uint8Array {
  const messageBytes = new TextEncoder().encode(message);
  const prefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`;
  const prefixBytes = new TextEncoder().encode(prefix);
  
  const fullMessage = new Uint8Array(prefixBytes.length + messageBytes.length);
  fullMessage.set(prefixBytes);
  fullMessage.set(messageBytes, prefixBytes.length);
  
  return keccak_256(fullMessage);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ENCRYPTION (using Web Crypto API + @noble/hashes)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Converts an ArrayBuffer to a base64 string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a base64 string to an ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Generates a cryptographically secure random salt
 */
export function generateSalt(): Uint8Array {
  return randomBytes(SALT_LENGTH);
}

/**
 * Generates a cryptographically secure IV for AES-GCM
 */
export function generateIV(): Uint8Array {
  return randomBytes(IV_LENGTH);
}

/**
 * Derives an encryption key from a password using PBKDF2
 * Uses @noble/hashes for PBKDF2, then imports to Web Crypto for AES
 */
export async function deriveEncryptionKey(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);

  // Use @noble/hashes for PBKDF2 derivation
  const derivedBytes = pbkdf2(sha256, passwordBytes, salt, {
    c: PBKDF2_ITERATIONS,
    dkLen: 32, // 256 bits
  });

  // Import the derived key into Web Crypto for AES-GCM
  return crypto.subtle.importKey(
    'raw',
    derivedBytes,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a private key with a password
 * Returns the encrypted data, salt, and IV as base64 strings
 */
export async function encryptPrivateKey(
  privateKey: string,
  password: string
): Promise<{ encrypted: string; salt: string; iv: string }> {
  const encoder = new TextEncoder();
  const data = encoder.encode(privateKey);

  const salt = generateSalt();
  const iv = generateIV();
  const key = await deriveEncryptionKey(password, salt);

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  return {
    encrypted: arrayBufferToBase64(encryptedBuffer),
    salt: arrayBufferToBase64(salt.buffer),
    iv: arrayBufferToBase64(iv.buffer),
  };
}

/**
 * Decrypts an encrypted private key with a password
 */
export async function decryptPrivateKey(
  encryptedBase64: string,
  saltBase64: string,
  ivBase64: string,
  password: string
): Promise<string> {
  const encryptedBuffer = base64ToArrayBuffer(encryptedBase64);
  const salt = new Uint8Array(base64ToArrayBuffer(saltBase64));
  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));

  const key = await deriveEncryptionKey(password, salt);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encryptedBuffer
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (error) {
    throw new Error('Failed to decrypt private key. Invalid password or corrupted data.');
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * UTILITY FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Generates a unique ID for session keys
 */
export function generateKeyId(): string {
  const bytes = randomBytes(16);
  return bytesToHex(bytes);
}

/**
 * Securely zeros out a Uint8Array
 */
export function secureZeroBytes(arr: Uint8Array): void {
  crypto.getRandomValues(arr); // Overwrite with random data first
  arr.fill(0);
}

/**
 * Validates that we're in a secure context (HTTPS or localhost)
 */
export function isSecureContext(): boolean {
  if (typeof window === 'undefined') return true; // Node.js
  return window.isSecureContext;
}

/**
 * Checks if Web Crypto API is available
 */
export function isCryptoAvailable(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
}

/**
 * Converts hex string to Uint8Array
 */
export function hexToUint8Array(hex: string): Uint8Array {
  return hexToBytes(hex.replace('0x', ''));
}

/**
 * Converts Uint8Array to hex string with 0x prefix
 */
export function uint8ArrayToHex(bytes: Uint8Array): string {
  return '0x' + bytesToHex(bytes);
}
