/**
 * Session Key Manager
 * Main class for managing browser-based session keys with Symmio Protocol InstantLayer
 */

import { ethers } from 'ethers';
import {
  encryptPrivateKey,
  decryptPrivateKey,
  generateKeyId,
  isCryptoAvailable,
  isSecureContext,
  generatePrivateKey,
  getAddress,
  generateWalletWithMnemonic,
  deriveKeyFromMnemonic,
  isValidMnemonic,
} from './crypto';
import { SessionKeyStorage, createStorage } from './storage';
import { InstantLayerClient } from './instant-layer';
import { SiweAuthClient } from './auth';
import {
  signOperation,
  signDelegation,
  createReplayHeader,
  createDelegationInfo,
} from './eip712';
import type {
  CreateSessionKeyOptions,
  StoredSessionKey,
  UnlockedSessionKey,
  StorageAdapter,
  SessionKeyEvent,
  SessionKeyEventListener,
  SignedOperation,
  AuthTokenResponse,
  Account,
} from './types';

/**
 * Options for initializing SessionKeyManager
 */
export interface SessionKeyManagerOptions {
  /** Custom storage adapter (defaults to IndexedDB/localStorage) */
  storage?: StorageAdapter;
  /** Auto-cleanup expired keys on initialization */
  autoCleanup?: boolean;
  /** Check for secure context (HTTPS) */
  requireSecureContext?: boolean;
}

/**
 * Options for creating a session key with mnemonic backup
 */
export interface CreateSessionKeyWithMnemonicOptions {
  /** Password to encrypt the key */
  password: string;
  /** Duration in seconds until key expires */
  expiryDuration: number;
  /** Function selectors to authorize */
  scopes: string[];
  /** Optional label for the key */
  label?: string;
  /** Account address to delegate for */
  accountAddress?: string;
  /** Chain ID (defaults to 1 for mainnet) */
  chainId?: number;
  /** Whether this is for PartyB (default: false for PartyA) */
  isPartyB?: boolean;
  /** Optional: use 24-word mnemonic instead of 12 */
  use24Words?: boolean;
}

/**
 * Result of creating a session key with mnemonic
 */
export interface SessionKeyWithMnemonic {
  sessionKey: StoredSessionKey;
  mnemonic: string;
}

/**
 * Options for recovering a session key from mnemonic
 */
export interface RecoverSessionKeyOptions {
  /** Password to encrypt the key */
  password: string;
  /** Duration in seconds until key expires */
  expiryDuration: number;
  /** Function selectors to authorize */
  scopes: string[];
  /** Optional label for the key */
  label?: string;
  /** Account address to delegate for */
  accountAddress?: string;
  /** Chain ID (defaults to 1 for mainnet) */
  chainId?: number;
  /** Whether this is for PartyB (default: false for PartyA) */
  isPartyB?: boolean;
  /** The mnemonic phrase to recover from */
  mnemonic: string;
  /** Optional: custom derivation path (default: m/44'/60'/0'/0/0) */
  derivationPath?: string;
}

/**
 * Session Key Manager - Main API for session key operations
 */
export class SessionKeyManager {
  private storage: SessionKeyStorage;
  private unlockedKeys: Map<string, UnlockedSessionKey> = new Map();
  private listeners: Set<SessionKeyEventListener> = new Set();
  private expiryTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

  constructor(options: SessionKeyManagerOptions = {}) {
    // Validate environment
    if (!isCryptoAvailable()) {
      throw new Error('Web Crypto API is not available. Session keys require a modern browser.');
    }

    if (options.requireSecureContext !== false && !isSecureContext()) {
      console.warn(
        'Session keys should be used in a secure context (HTTPS). ' +
        'Your keys may be vulnerable to interception.'
      );
    }

    this.storage = new SessionKeyStorage(options.storage || createStorage());

    // Auto-cleanup expired keys
    if (options.autoCleanup !== false) {
      this.cleanupExpired().catch(console.error);
    }
  }

  /**
   * Creates a new session key
   */
  async create(options: CreateSessionKeyOptions): Promise<StoredSessionKey> {
    // Validate inputs
    this.validateCreateOptions(options);

    // Generate new private key using @noble/curves (audited, constant-time)
    const privateKey = generatePrivateKey();
    const address = getAddress(privateKey);

    return this.createFromPrivateKey(privateKey, address, options);
  }

  /**
   * Creates a new session key with mnemonic backup
   * The mnemonic is returned once and should be shown to the user for backup
   * 
   * @returns The session key and the mnemonic (show to user, do not store)
   */
  async createWithMnemonic(
    options: CreateSessionKeyWithMnemonicOptions
  ): Promise<SessionKeyWithMnemonic> {
    this.validateCreateOptions(options);

    // Generate wallet with mnemonic using @scure/bip39
    const { mnemonic, privateKey, address } = generateWalletWithMnemonic();
    
    const sessionKey = await this.createFromPrivateKey(privateKey, address, options);

    return { sessionKey, mnemonic };
  }

  /**
   * Recovers a session key from a mnemonic phrase
   */
  async recoverFromMnemonic(options: RecoverSessionKeyOptions): Promise<StoredSessionKey> {
    this.validateCreateOptions(options);

    if (!isValidMnemonic(options.mnemonic)) {
      throw new Error('Invalid mnemonic phrase');
    }

    const privateKey = deriveKeyFromMnemonic(
      options.mnemonic, 
      options.derivationPath
    );
    const address = getAddress(privateKey);

    return this.createFromPrivateKey(privateKey, address, options);
  }

  /**
   * Validates creation options
   */
  private validateCreateOptions(options: CreateSessionKeyOptions): void {
    if (!options.password || options.password.length < 8) {
      throw new Error('Password must be at least 8 characters');
    }

    if (options.expiryDuration <= 0) {
      throw new Error('Expiry duration must be positive');
    }

    if (!options.scopes || options.scopes.length === 0) {
      throw new Error('At least one scope must be specified');
    }
  }

  /**
   * Internal helper to create session key from private key
   */
  private async createFromPrivateKey(
    privateKey: string,
    address: string,
    options: CreateSessionKeyOptions
  ): Promise<StoredSessionKey> {
    // Encrypt the private key
    const encrypted = await encryptPrivateKey(privateKey, options.password);

    // Create stored key object
    const now = Math.floor(Date.now() / 1000);
    const sessionKey: StoredSessionKey = {
      id: generateKeyId(),
      encryptedPrivateKey: encrypted.encrypted,
      salt: encrypted.salt,
      iv: encrypted.iv,
      address,
      expiry: now + options.expiryDuration,
      createdAt: now,
      scopes: options.scopes,
      label: options.label,
      accountAddress: options.accountAddress,
      chainId: options.chainId || 1,
      isPartyB: options.isPartyB || false,
    };

    // Save to storage
    await this.storage.save(sessionKey);

    // Emit event
    this.emit({ type: 'created', key: sessionKey });

    // Schedule expiry notification
    this.scheduleExpiryNotification(sessionKey);

    return sessionKey;
  }

  /**
   * Unlocks a session key for signing
   */
  async unlock(keyId: string, password: string): Promise<UnlockedSessionKey> {
    // Check if already unlocked
    const existing = this.unlockedKeys.get(keyId);
    if (existing) {
      if (existing.expiry * 1000 < Date.now()) {
        this.unlockedKeys.delete(keyId);
        throw new Error('Session key has expired');
      }
      return existing;
    }

    // Load from storage
    const stored = await this.storage.load(keyId);
    if (!stored) {
      throw new Error(`Session key not found: ${keyId}`);
    }

    // Check expiry
    if (stored.expiry * 1000 < Date.now()) {
      this.emit({ type: 'expired', keyId });
      throw new Error('Session key has expired');
    }

    // Decrypt
    const privateKey = await decryptPrivateKey(
      stored.encryptedPrivateKey,
      stored.salt,
      stored.iv,
      password
    );

    // Create unlocked key
    const unlocked: UnlockedSessionKey = {
      id: stored.id,
      privateKey,
      address: stored.address,
      expiry: stored.expiry,
      scopes: stored.scopes,
      accountAddress: stored.accountAddress,
      chainId: stored.chainId,
      isPartyB: stored.isPartyB,
    };

    // Cache the unlocked key
    this.unlockedKeys.set(keyId, unlocked);

    // Emit event
    this.emit({ type: 'unlocked', key: unlocked });

    return unlocked;
  }

  /**
   * Locks a session key (clears from memory)
   */
  lock(keyId: string): void {
    const wasUnlocked = this.unlockedKeys.has(keyId);
    this.unlockedKeys.delete(keyId);
    
    if (wasUnlocked) {
      this.emit({ type: 'locked', keyId });
    }
  }

  /**
   * Locks all unlocked keys
   */
  lockAll(): void {
    for (const keyId of this.unlockedKeys.keys()) {
      this.lock(keyId);
    }
  }

  /**
   * Gets an unlocked key (throws if not unlocked)
   */
  getUnlocked(keyId: string): UnlockedSessionKey {
    const key = this.unlockedKeys.get(keyId);
    if (!key) {
      throw new Error(`Session key not unlocked: ${keyId}`);
    }
    if (key.expiry * 1000 < Date.now()) {
      this.unlockedKeys.delete(keyId);
      throw new Error('Session key has expired');
    }
    return key;
  }

  /**
   * Checks if a key is unlocked
   */
  isUnlocked(keyId: string): boolean {
    return this.unlockedKeys.has(keyId);
  }

  /**
   * Signs a message with an unlocked session key
   */
  async signMessage(keyId: string, message: string): Promise<string> {
    const unlocked = this.getUnlocked(keyId);
    const wallet = new ethers.Wallet(unlocked.privateKey);
    return wallet.signMessage(message);
  }

  /**
   * Signs typed data (EIP-712) with an unlocked session key
   */
  async signTypedData(
    keyId: string,
    domain: ethers.TypedDataDomain,
    types: Record<string, ethers.TypedDataField[]>,
    value: Record<string, unknown>
  ): Promise<string> {
    const unlocked = this.getUnlocked(keyId);
    const wallet = new ethers.Wallet(unlocked.privateKey);
    return wallet.signTypedData(domain, types, value);
  }

  /**
   * Gets a stored session key by ID
   */
  async get(keyId: string): Promise<StoredSessionKey | null> {
    return this.storage.load(keyId);
  }

  /**
   * Lists all stored session keys
   */
  async list(): Promise<StoredSessionKey[]> {
    return this.storage.listAll();
  }

  /**
   * Lists only valid (non-expired) session keys
   */
  async listValid(): Promise<StoredSessionKey[]> {
    return this.storage.listValid();
  }

  /**
   * Deletes a session key
   */
  async delete(keyId: string): Promise<void> {
    // Lock if unlocked
    this.lock(keyId);
    
    // Clear expiry timer
    const timer = this.expiryTimers.get(keyId);
    if (timer) {
      clearTimeout(timer);
      this.expiryTimers.delete(keyId);
    }

    // Remove from storage
    await this.storage.remove(keyId);
    
    // Emit event
    this.emit({ type: 'deleted', keyId });
  }

  /**
   * Cleans up expired session keys
   */
  async cleanupExpired(): Promise<string[]> {
    const removed = await this.storage.clearExpired();
    for (const keyId of removed) {
      this.lock(keyId);
      this.emit({ type: 'expired', keyId });
    }
    return removed;
  }

  /**
   * Clears all session keys
   */
  async clearAll(): Promise<void> {
    this.lockAll();
    await this.storage.clearAll();
    
    // Clear all expiry timers
    for (const timer of this.expiryTimers.values()) {
      clearTimeout(timer);
    }
    this.expiryTimers.clear();
  }

  /* ═══════════════════════════════════════════════════════════════════════════
   * INSTANT LAYER INTEGRATION
   * ═══════════════════════════════════════════════════════════════════════════ */

  /**
   * Delegates access to the session key via owner's signature (gasless for owner)
   */
  async delegateToSessionKeyBySig(
    keyId: string,
    ownerWallet: ethers.Wallet,
    instantLayer: InstantLayerClient,
    submitter?: ethers.Signer
  ): Promise<ethers.TransactionReceipt> {
    const stored = await this.get(keyId);
    if (!stored) {
      throw new Error(`Session key not found: ${keyId}`);
    }

    if (!stored.accountAddress) {
      throw new Error('Session key has no account address configured');
    }

    // Get current delegation nonce
    const nonce = await instantLayer.getDelegationNonce(stored.accountAddress);
    
    // Create delegation info
    const delegationInfo = createDelegationInfo({
      accountAddress: stored.accountAddress,
      isPartyB: stored.isPartyB,
      delegatedSigner: stored.address,
      selectors: stored.scopes,
      expiryTimestamp: BigInt(stored.expiry),
    });

    // Create replay header
    const replayHeader = createReplayHeader({
      nonce: nonce + 1n,
      deadlineSeconds: 3600,
    });

    // Sign the delegation
    const { signedDelegation, signature } = await signDelegation(
      ownerWallet,
      instantLayer.getDomain(),
      delegationInfo,
      replayHeader
    );

    // Submit (can be submitted by anyone)
    const signer = submitter || ownerWallet;
    const contract = new ethers.Contract(
      instantLayer.instantLayerAddress,
      ['function grantBatchDelegationBySig(((address,bool),address,bytes4[],uint256),(uint256,uint256,bytes32),bytes) external'],
      signer
    );

    const tx = await contract.grantBatchDelegationBySig(
      signedDelegation,
      signature
    );
    const receipt = await tx.wait();
    
    this.emit({ type: 'delegated', keyId, txHash: receipt.hash });
    return receipt;
  }

  /**
   * Delegates access directly (owner must submit tx)
   */
  async delegateToSessionKeyDirect(
    keyId: string,
    ownerSigner: ethers.Signer,
    instantLayer: InstantLayerClient
  ): Promise<ethers.TransactionReceipt> {
    const stored = await this.get(keyId);
    if (!stored) {
      throw new Error(`Session key not found: ${keyId}`);
    }

    if (!stored.accountAddress) {
      throw new Error('Session key has no account address configured');
    }

    const receipt = await instantLayer.grantDelegationDirect(
      ownerSigner,
      stored.address,
      stored.accountAddress,
      stored.scopes,
      BigInt(stored.expiry)
    );

    this.emit({ type: 'delegated', keyId, txHash: receipt.hash });
    return receipt;
  }

  /**
   * Signs an operation with the session key for execution via InstantLayer
   */
  async signOperation(
    keyId: string,
    target: string,
    callData: string,
    instantLayer: InstantLayerClient,
    options?: {
      nonce?: bigint;
      deadline?: bigint;
      deadlineSeconds?: number;
    }
  ): Promise<{ signedOperation: SignedOperation; signature: string }> {
    const unlocked = this.getUnlocked(keyId);
    const wallet = new ethers.Wallet(unlocked.privateKey);

    if (!unlocked.accountAddress) {
      throw new Error('Session key has no account address configured');
    }

    const account: Account = {
      addr: unlocked.accountAddress,
      isPartyB: unlocked.isPartyB,
    };

    const replayHeader = createReplayHeader({
      nonce: options?.nonce,
      deadline: options?.deadline,
      deadlineSeconds: options?.deadlineSeconds ?? 300,
    });

    return signOperation(wallet, instantLayer.getDomain(), {
      target,
      callData,
      signerAccount: account,
      replayAttackHeader: replayHeader,
    });
  }

  /**
   * Initiates revocation of the session key delegation
   */
  async initiateRevokeDelegation(
    keyId: string,
    signer: ethers.Signer,
    instantLayer: InstantLayerClient
  ): Promise<ethers.TransactionReceipt> {
    const stored = await this.get(keyId);
    if (!stored) {
      throw new Error(`Session key not found: ${keyId}`);
    }

    if (!stored.accountAddress) {
      throw new Error('Session key has no account address configured');
    }

    return instantLayer.initiateRevokeDelegation(
      signer,
      stored.accountAddress,
      stored.address,
      stored.scopes
    );
  }

  /**
   * Finalizes revocation after cooldown
   */
  async finalizeRevokeDelegation(
    keyId: string,
    signer: ethers.Signer,
    instantLayer: InstantLayerClient
  ): Promise<ethers.TransactionReceipt> {
    const stored = await this.get(keyId);
    if (!stored) {
      throw new Error(`Session key not found: ${keyId}`);
    }

    if (!stored.accountAddress) {
      throw new Error('Session key has no account address configured');
    }

    const receipt = await instantLayer.finalizeRevokeDelegation(
      signer,
      stored.accountAddress,
      stored.address,
      stored.scopes
    );

    this.emit({ type: 'revoked', keyId, txHash: receipt.hash });
    return receipt;
  }

  /**
   * Checks if the session key delegation is active
   */
  async isDelegationActive(
    keyId: string,
    instantLayer: InstantLayerClient
  ): Promise<boolean> {
    const stored = await this.get(keyId);
    if (!stored || !stored.accountAddress) {
      return false;
    }

    // Check each selector
    for (const selector of stored.scopes) {
      const active = await instantLayer.isDelegationActive(
        stored.accountAddress,
        stored.address,
        selector
      );
      if (!active) return false;
    }

    return true;
  }

  /* ═══════════════════════════════════════════════════════════════════════════
   * AUTHENTICATION
   * ═══════════════════════════════════════════════════════════════════════════ */

  /**
   * Authenticates with a SIWE-compatible server using a session key
   */
  async authenticate(
    keyId: string,
    authClient: SiweAuthClient,
    options?: {
      statement?: string;
      expirySeconds?: number;
      resources?: string[];
    }
  ): Promise<AuthTokenResponse> {
    const unlocked = this.getUnlocked(keyId);
    return authClient.authenticate(unlocked, options);
  }

  /* ═══════════════════════════════════════════════════════════════════════════
   * EVENT HANDLING
   * ═══════════════════════════════════════════════════════════════════════════ */

  /**
   * Subscribes to session key events
   */
  on(listener: SessionKeyEventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Removes an event listener
   */
  off(listener: SessionKeyEventListener): void {
    this.listeners.delete(listener);
  }

  private emit(event: SessionKeyEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch (error) {
        console.error('Error in session key event listener:', error);
      }
    }
  }

  private scheduleExpiryNotification(key: StoredSessionKey): void {
    const timeUntilExpiry = key.expiry * 1000 - Date.now();
    if (timeUntilExpiry <= 0) return;

    const timer = setTimeout(() => {
      this.emit({ type: 'expired', keyId: key.id });
      this.lock(key.id);
      this.expiryTimers.delete(key.id);
    }, timeUntilExpiry);

    this.expiryTimers.set(key.id, timer);
  }

  /* ═══════════════════════════════════════════════════════════════════════════
   * UTILITIES
   * ═══════════════════════════════════════════════════════════════════════════ */

  /**
   * Gets an ethers Wallet instance from an unlocked key
   */
  getWallet(keyId: string, provider?: ethers.Provider): ethers.Wallet {
    const unlocked = this.getUnlocked(keyId);
    const wallet = new ethers.Wallet(unlocked.privateKey);
    return provider ? wallet.connect(provider) : wallet;
  }

  /**
   * Checks if a session key is valid (exists and not expired)
   */
  async isValid(keyId: string): Promise<boolean> {
    const stored = await this.get(keyId);
    if (!stored) return false;
    return stored.expiry * 1000 > Date.now();
  }

  /**
   * Gets the time remaining until a key expires (in seconds)
   */
  async getTimeRemaining(keyId: string): Promise<number> {
    const stored = await this.get(keyId);
    if (!stored) return 0;
    return Math.max(0, stored.expiry - Math.floor(Date.now() / 1000));
  }

  /**
   * Updates the label of a session key
   */
  async updateLabel(keyId: string, label: string): Promise<void> {
    const stored = await this.get(keyId);
    if (!stored) {
      throw new Error(`Session key not found: ${keyId}`);
    }
    stored.label = label;
    await this.storage.save(stored);
  }
}

/**
 * Creates a new SessionKeyManager with default options
 */
export function createSessionKeyManager(
  options?: SessionKeyManagerOptions
): SessionKeyManager {
  return new SessionKeyManager(options);
}
