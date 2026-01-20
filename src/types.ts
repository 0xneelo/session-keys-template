/**
 * Session Key Types for Symmio Protocol InstantLayer Integration
 */

/**
 * Represents a stored session key with metadata
 */
export interface StoredSessionKey {
  /** Unique identifier for the session key */
  id: string;
  /** Encrypted private key (base64 encoded) */
  encryptedPrivateKey: string;
  /** Salt used for key derivation (base64 encoded) */
  salt: string;
  /** IV used for encryption (base64 encoded) */
  iv: string;
  /** Public address derived from the session key */
  address: string;
  /** Unix timestamp when the key expires */
  expiry: number;
  /** Unix timestamp when the key was created */
  createdAt: number;
  /** Symmio function selectors this key is authorized for */
  scopes: string[];
  /** Optional label for identifying the key */
  label?: string;
  /** Account address this key is delegated for (PartyA account) */
  accountAddress?: string;
  /** Chain ID this key was created for */
  chainId: number;
  /** Whether this is for a PartyB account */
  isPartyB: boolean;
}

/**
 * Options for creating a new session key
 */
export interface CreateSessionKeyOptions {
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
}

/**
 * Decrypted session key ready for signing
 */
export interface UnlockedSessionKey {
  id: string;
  privateKey: string;
  address: string;
  expiry: number;
  scopes: string[];
  accountAddress?: string;
  chainId: number;
  isPartyB: boolean;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * INSTANT LAYER TYPES - Matching the Solidity contract structs
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Account struct from InstantLayer
 * @param addr The actual account address (PartyA account or PartyB address)
 * @param isPartyB Whether this operation targets a PartyB or not
 */
export interface Account {
  addr: string;
  isPartyB: boolean;
}

/**
 * ReplayAttackHeader struct from InstantLayer
 * @param nonce Sequential counter (0 = disabled/salt-only, >0 = enforced ordering)
 * @param deadline UNIX timestamp after which the operation expires
 * @param salt Unique 32-byte value for operation uniqueness
 */
export interface ReplayAttackHeader {
  nonce: bigint;
  deadline: bigint;
  salt: string; // bytes32 as hex string
}

/**
 * SignedOperation struct from InstantLayer
 */
export interface SignedOperation {
  signer: string;
  target: string;
  callData: string; // bytes as hex string
  signerAccount: Account;
  replayAttackHeader: ReplayAttackHeader;
}

/**
 * DelegationInfo struct from InstantLayer
 */
export interface DelegationInfo {
  account: Account;
  delegatedSigner: string;
  selectors: string[]; // bytes4[] as hex strings
  expiryTimestamp: bigint;
}

/**
 * SignedDelegation struct from InstantLayer
 */
export interface SignedDelegation {
  delegationInfo: DelegationInfo;
  replayAttackHeader: ReplayAttackHeader;
}

/**
 * Parameters for granting delegation
 */
export interface GrantDelegationParams {
  /** Account granting delegation */
  account: Account;
  /** Address receiving delegation (session key address) */
  delegatedSigner: string;
  /** Function selectors to delegate */
  selectors: string[];
  /** Unix timestamp when delegation expires */
  expiryTimestamp: bigint;
}

/**
 * Parameters for executing an operation via InstantLayer
 */
export interface ExecuteOperationParams {
  /** Target contract to call */
  target: string;
  /** Encoded function call data */
  callData: string;
  /** Account context */
  account: Account;
  /** Optional deadline (0 for no deadline) */
  deadline?: bigint;
  /** Optional nonce (0 for salt-only replay protection) */
  nonce?: bigint;
}

/**
 * Symmio contract addresses for different networks
 */
export interface SymmioAddresses {
  symmio: string;
  instantLayer: string;
  accountHub?: string;
}

/**
 * Network configuration for Symmio
 */
export interface NetworkConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  addresses: SymmioAddresses;
  solverEndpoint?: string;
}

/**
 * Common Symmio function selectors for delegation
 */
export const SYMMIO_SELECTORS = {
  // Trading functions
  SEND_QUOTE: '0x6faae4a7',
  SEND_QUOTE_WITH_REFERRER: '0x9a1c5ade',
  REQUEST_TO_CANCEL_QUOTE: '0xe2c4de88',
  REQUEST_TO_CLOSE_POSITION: '0x93e57bf1',
  REQUEST_TO_CANCEL_CLOSE_REQUEST: '0x6a2e31cd',
  FORCE_CLOSE_POSITION: '0xa08beb38',
  
  // Account functions
  ALLOCATE: '0x12e8e2c3',
  DEALLOCATE: '0x54e6d5d8',
  DEPOSIT_AND_ALLOCATE: '0x55dc9f8e',
  WITHDRAW: '0x3ccfd60b',
  
  // Liquidation
  LIQUIDATE_POSITIONS_PARTY_A: '0x57a4d276',
  
  // Settlement
  SETTLE_UPNL: '0x4c27c9bb',
} as const;

/**
 * Predefined scope bundles for common use cases
 */
export const SCOPE_BUNDLES = {
  /** Basic trading: open and close positions */
  TRADING_BASIC: [
    SYMMIO_SELECTORS.SEND_QUOTE,
    SYMMIO_SELECTORS.REQUEST_TO_CLOSE_POSITION,
    SYMMIO_SELECTORS.REQUEST_TO_CANCEL_QUOTE,
  ],
  
  /** Full trading: all trading operations */
  TRADING_FULL: [
    SYMMIO_SELECTORS.SEND_QUOTE,
    SYMMIO_SELECTORS.SEND_QUOTE_WITH_REFERRER,
    SYMMIO_SELECTORS.REQUEST_TO_CLOSE_POSITION,
    SYMMIO_SELECTORS.REQUEST_TO_CANCEL_QUOTE,
    SYMMIO_SELECTORS.REQUEST_TO_CANCEL_CLOSE_REQUEST,
    SYMMIO_SELECTORS.FORCE_CLOSE_POSITION,
  ],
  
  /** Account management: allocate and deallocate */
  ACCOUNT_MANAGEMENT: [
    SYMMIO_SELECTORS.ALLOCATE,
    SYMMIO_SELECTORS.DEALLOCATE,
    SYMMIO_SELECTORS.DEPOSIT_AND_ALLOCATE,
  ],
  
  /** Everything: full access */
  FULL_ACCESS: Object.values(SYMMIO_SELECTORS),
} as const;

/**
 * EIP-712 Domain for InstantLayer
 */
export interface InstantLayerDomain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string;
}

/**
 * SIWE message parameters
 */
export interface SiweParams {
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version?: string;
  chainId: number;
  nonce: string;
  issuedAt?: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  resources?: string[];
}

/**
 * Authentication token response
 */
export interface AuthTokenResponse {
  accessToken: string;
  expiresAt: number;
  accountAddress: string;
}

/**
 * Storage adapter interface for custom storage implementations
 */
export interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  keys(): Promise<string[]>;
}

/**
 * Events emitted by SessionKeyManager
 */
export type SessionKeyEvent = 
  | { type: 'created'; key: StoredSessionKey }
  | { type: 'unlocked'; key: UnlockedSessionKey }
  | { type: 'locked'; keyId: string }
  | { type: 'deleted'; keyId: string }
  | { type: 'expired'; keyId: string }
  | { type: 'delegated'; keyId: string; txHash: string }
  | { type: 'revoked'; keyId: string; txHash: string };

export type SessionKeyEventListener = (event: SessionKeyEvent) => void;
