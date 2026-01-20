/**
 * @symmio/session-keys
 * 
 * Browser-based session key management for Symmio Protocol InstantLayer.
 * Generate, store, and manage temporary private keys that can be delegated
 * access via Symmio's InstantLayer contract using EIP-712 signatures.
 * 
 * @example
 * ```typescript
 * import { 
 *   SessionKeyManager, 
 *   InstantLayerClient,
 *   SCOPE_BUNDLES 
 * } from '@symmio/session-keys';
 * 
 * // Create manager
 * const manager = new SessionKeyManager();
 * 
 * // Create a session key
 * const sessionKey = await manager.create({
 *   password: 'secure-password',
 *   expiryDuration: 86400, // 24 hours
 *   scopes: SCOPE_BUNDLES.TRADING_BASIC,
 *   accountAddress: '0x...',
 *   chainId: 42161,
 * });
 * 
 * // Delegate via owner signature (gasless for owner)
 * const instantLayer = InstantLayerClient.fromAddresses(provider, addresses, 42161);
 * await manager.delegateToSessionKeyBySig(sessionKey.id, ownerWallet, instantLayer);
 * 
 * // Unlock and sign operations
 * await manager.unlock(sessionKey.id, 'secure-password');
 * const { signedOperation, signature } = await manager.signOperation(
 *   sessionKey.id,
 *   symmioAddress,
 *   callData,
 *   instantLayer
 * );
 * ```
 */

// Core manager
export { SessionKeyManager, createSessionKeyManager } from './manager';
export type { 
  SessionKeyManagerOptions,
  CreateSessionKeyWithMnemonicOptions,
  SessionKeyWithMnemonic,
  RecoverSessionKeyOptions,
} from './manager';

// InstantLayer integration
export { 
  InstantLayerClient, 
  INSTANT_LAYER_ABI, 
  KNOWN_NETWORKS,
  isValidAddress,
} from './instant-layer';

// EIP-712 signing utilities
export {
  EIP712_TYPES,
  createInstantLayerDomain,
  generateSalt,
  createReplayHeader,
  signDelegation,
  signOperation,
  createOperation,
  createDelegationInfo,
  encodeFunctionCall,
  decodeFunctionResult,
  computeSelector,
  isValidSelector,
  normalizeSelectors,
} from './eip712';

// Authentication
export {
  SiweAuthClient,
  buildSiweMessage,
  signSiweMessage,
  createSiweMessage,
  generateNonce,
  verifySiweSignature,
} from './auth';

// Storage adapters
export {
  IndexedDBStorage,
  LocalStorageAdapter,
  MemoryStorage,
  SessionKeyStorage,
  createStorage,
} from './storage';

// Crypto utilities (@noble/curves, @noble/hashes, @scure/bip39)
export {
  // Key generation
  generatePrivateKey,
  isValidPrivateKey,
  getPublicKey,
  getAddress,
  toChecksumAddress,
  
  // Mnemonic support
  generateMnemonicPhrase,
  isValidMnemonic,
  deriveKeyFromMnemonic,
  generateWalletWithMnemonic,
  
  // Signing
  signHash,
  hashMessage,
  
  // Encryption
  encryptPrivateKey,
  decryptPrivateKey,
  deriveEncryptionKey,
  
  // Utilities
  generateKeyId,
  generateSalt,
  generateIV,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  hexToUint8Array,
  uint8ArrayToHex,
  secureZeroBytes,
  isCryptoAvailable,
  isSecureContext,
} from './crypto';

// Types
export type {
  StoredSessionKey,
  CreateSessionKeyOptions,
  UnlockedSessionKey,
  Account,
  ReplayAttackHeader,
  SignedOperation,
  SignedDelegation,
  DelegationInfo,
  GrantDelegationParams,
  ExecuteOperationParams,
  SymmioAddresses,
  NetworkConfig,
  InstantLayerDomain,
  SiweParams,
  AuthTokenResponse,
  StorageAdapter,
  SessionKeyEvent,
  SessionKeyEventListener,
} from './types';

// Constants
export {
  SYMMIO_SELECTORS,
  SCOPE_BUNDLES,
} from './types';

// Re-export legacy symmio module for backward compatibility
export { SymmioClient, MULTI_ACCOUNT_ABI } from './symmio';
