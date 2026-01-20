/**
 * Symmio InstantLayer Integration
 * 
 * Handles delegation and operation execution via the InstantLayer contract
 */

import { ethers } from 'ethers';
import {
  createInstantLayerDomain,
  signDelegation,
  signOperation,
  createReplayHeader,
  createDelegationInfo,
} from './eip712';
import type {
  Account,
  SignedOperation,
  SignedDelegation,
  DelegationInfo,
  ReplayAttackHeader,
  NetworkConfig,
  SymmioAddresses,
  InstantLayerDomain,
} from './types';

/**
 * InstantLayer contract ABI (relevant functions for session keys)
 */
export const INSTANT_LAYER_ABI = [
  // Delegation management
  'function grantBatchDelegationBySig(((' +
    '(address addr, bool isPartyB) account,' +
    'address delegatedSigner,' +
    'bytes4[] selectors,' +
    'uint256 expiryTimestamp' +
  ') delegationInfo,' +
  '(uint256 nonce, uint256 deadline, bytes32 salt) replayAttackHeader) signedDelegation, bytes signature) external',
  
  'function grantDelegation((' +
    '(address addr, bool isPartyB) account,' +
    'address delegatedSigner,' +
    'bytes4[] selectors,' +
    'uint256 expiryTimestamp' +
  ') info) external',
  
  'function initiateRevokeDelegation((address addr, bool isPartyB) account, address delegate, bytes4[] selectors) external',
  'function finalizeRevokeDelegation((address addr, bool isPartyB) account, address delegate, bytes4[] selectors) external',
  
  // Operation execution
  'function executeBatch((' +
    'address signer,' +
    'address target,' +
    'bytes callData,' +
    '(address addr, bool isPartyB) signerAccount,' +
    '(uint256 nonce, uint256 deadline, bytes32 salt) replayAttackHeader' +
  ')[] signedOps, bytes[] signatures) external',
  
  'function executeTemplate(uint256 templateId, (' +
    'address signer,' +
    'address target,' +
    'bytes callData,' +
    '(address addr, bool isPartyB) signerAccount,' +
    '(uint256 nonce, uint256 deadline, bytes32 salt) replayAttackHeader' +
  ')[] signedOps, bytes[] signatures) external',
  
  // View functions
  'function isDelegationActive(address delegator, address delegate, bytes4 selector) external view returns (bool)',
  'function delegations(address delegator, address delegate, bytes4 selector) external view returns (uint256)',
  'function delegationNonces(address account) external view returns (uint256)',
  'function nonces(address account) external view returns (uint256)',
  'function revocationCooldown() external view returns (uint256)',
  'function pendingRevocationEta(address delegator, address delegate, bytes4 selector) external view returns (uint256)',
  'function usedOperationHashes(bytes32 hash) external view returns (bool)',
  'function usedDelegationHashes(bytes32 hash) external view returns (bool)',
  'function domainSeparator() external view returns (bytes32)',
  'function getOperationHash((' +
    'address signer,' +
    'address target,' +
    'bytes callData,' +
    '(address addr, bool isPartyB) signerAccount,' +
    '(uint256 nonce, uint256 deadline, bytes32 salt) replayAttackHeader' +
  ') signedOp) external view returns (bytes32)',
  'function getDelegationHash((' +
    '(address addr, bool isPartyB) account,' +
    'address delegatedSigner,' +
    'bytes4[] selectors,' +
    'uint256 expiryTimestamp' +
  ') delegationInfo, (uint256 nonce, uint256 deadline, bytes32 salt) replayAttackHeader) external view returns (bytes32)',
  
  // Events
  'event DelegationGranted(address indexed delegator, address indexed delegate, bytes4 selector, uint256 expiryTimestamp)',
  'event RevocationScheduled(address indexed delegator, address indexed delegate, bytes4 selector, uint256 eta)',
  'event DelegationSelectorRevoked(address indexed delegator, address indexed delegate, bytes4 selector)',
  'event BatchExecuted(address indexed executor, uint256 operationCount)',
  'event OperationsExecuted(uint256 indexed templateId, address indexed executor)',
];

/**
 * Known Symmio network configurations with InstantLayer
 */
export const KNOWN_NETWORKS: Record<number, NetworkConfig> = {
  // Arbitrum Mainnet
  42161: {
    chainId: 42161,
    name: 'Arbitrum One',
    rpcUrl: 'https://arb1.arbitrum.io/rpc',
    addresses: {
      symmio: '0x...', // Update with actual address
      instantLayer: '0x...', // Update with actual address
      accountHub: '0x...',
    },
    solverEndpoint: 'https://solver.symm.io',
  },
  // Base Mainnet
  8453: {
    chainId: 8453,
    name: 'Base',
    rpcUrl: 'https://mainnet.base.org',
    addresses: {
      symmio: '0x...',
      instantLayer: '0x...',
      accountHub: '0x...',
    },
    solverEndpoint: 'https://solver-base.symm.io',
  },
  // BNB Chain
  56: {
    chainId: 56,
    name: 'BNB Smart Chain',
    rpcUrl: 'https://bsc-dataseed.binance.org',
    addresses: {
      symmio: '0x...',
      instantLayer: '0x...',
      accountHub: '0x...',
    },
    solverEndpoint: 'https://solver-bsc.symm.io',
  },
};

/**
 * InstantLayer client for session key delegation and operations
 */
export class InstantLayerClient {
  private provider: ethers.Provider;
  private contract: ethers.Contract;
  private addresses: SymmioAddresses;
  private chainId: number;
  private domain: InstantLayerDomain;

  constructor(
    providerOrSigner: ethers.Provider | ethers.Signer,
    addresses: SymmioAddresses,
    chainId: number
  ) {
    if ('provider' in providerOrSigner && providerOrSigner.provider) {
      this.provider = providerOrSigner.provider;
    } else {
      this.provider = providerOrSigner as ethers.Provider;
    }
    
    this.addresses = addresses;
    this.chainId = chainId;
    this.contract = new ethers.Contract(
      addresses.instantLayer,
      INSTANT_LAYER_ABI,
      providerOrSigner
    );
    this.domain = createInstantLayerDomain(chainId, addresses.instantLayer);
  }

  /**
   * Creates an InstantLayerClient from a network config
   */
  static fromNetwork(
    chainId: number,
    providerOrSigner?: ethers.Provider | ethers.Signer
  ): InstantLayerClient {
    const network = KNOWN_NETWORKS[chainId];
    if (!network) {
      throw new Error(`Unknown network: ${chainId}`);
    }

    const provider = providerOrSigner || new ethers.JsonRpcProvider(network.rpcUrl);
    return new InstantLayerClient(provider, network.addresses, chainId);
  }

  /**
   * Creates a client with custom addresses
   */
  static fromAddresses(
    providerOrSigner: ethers.Provider | ethers.Signer,
    addresses: SymmioAddresses,
    chainId: number
  ): InstantLayerClient {
    return new InstantLayerClient(providerOrSigner, addresses, chainId);
  }

  /**
   * Gets the EIP-712 domain for this InstantLayer
   */
  getDomain(): InstantLayerDomain {
    return this.domain;
  }

  /* ═══════════════════════════════════════════════════════════════════════════
   * DELEGATION MANAGEMENT
   * ═══════════════════════════════════════════════════════════════════════════ */

  /**
   * Grants delegation to a session key using the owner's signature
   * This is the gasless way to delegate - owner signs, anyone can submit
   */
  async grantDelegationBySig(
    ownerWallet: ethers.Wallet,
    sessionKeyAddress: string,
    accountAddress: string,
    selectors: string[],
    expiryTimestamp: bigint,
    submitter?: ethers.Signer
  ): Promise<ethers.TransactionReceipt> {
    // Get current delegation nonce
    const nonce = await this.getDelegationNonce(accountAddress);
    
    // Create delegation info
    const delegationInfo = createDelegationInfo({
      accountAddress,
      isPartyB: false,
      delegatedSigner: sessionKeyAddress,
      selectors,
      expiryTimestamp,
    });

    // Create replay header with next nonce
    const replayHeader = createReplayHeader({
      nonce: nonce + 1n,
      deadlineSeconds: 3600, // 1 hour deadline
    });

    // Sign the delegation
    const { signedDelegation, signature } = await signDelegation(
      ownerWallet,
      this.domain,
      delegationInfo,
      replayHeader
    );

    // Submit the transaction (owner or anyone can submit)
    const signer = submitter || ownerWallet;
    const contract = this.contract.connect(signer);
    
    const tx = await contract.grantBatchDelegationBySig(
      signedDelegation,
      signature
    );

    return tx.wait();
  }

  /**
   * Grants delegation directly (must be called by account owner)
   */
  async grantDelegationDirect(
    ownerSigner: ethers.Signer,
    sessionKeyAddress: string,
    accountAddress: string,
    selectors: string[],
    expiryTimestamp: bigint
  ): Promise<ethers.TransactionReceipt> {
    const delegationInfo: DelegationInfo = {
      account: { addr: accountAddress, isPartyB: false },
      delegatedSigner: sessionKeyAddress,
      selectors,
      expiryTimestamp,
    };

    const contract = this.contract.connect(ownerSigner);
    const tx = await contract.grantDelegation(delegationInfo);
    return tx.wait();
  }

  /**
   * Initiates revocation of delegation (starts cooldown)
   */
  async initiateRevokeDelegation(
    signer: ethers.Signer,
    accountAddress: string,
    delegateAddress: string,
    selectors: string[]
  ): Promise<ethers.TransactionReceipt> {
    const account: Account = { addr: accountAddress, isPartyB: false };
    const contract = this.contract.connect(signer);
    const tx = await contract.initiateRevokeDelegation(account, delegateAddress, selectors);
    return tx.wait();
  }

  /**
   * Finalizes revocation after cooldown period
   */
  async finalizeRevokeDelegation(
    signer: ethers.Signer,
    accountAddress: string,
    delegateAddress: string,
    selectors: string[]
  ): Promise<ethers.TransactionReceipt> {
    const account: Account = { addr: accountAddress, isPartyB: false };
    const contract = this.contract.connect(signer);
    const tx = await contract.finalizeRevokeDelegation(account, delegateAddress, selectors);
    return tx.wait();
  }

  /* ═══════════════════════════════════════════════════════════════════════════
   * OPERATION EXECUTION
   * ═══════════════════════════════════════════════════════════════════════════ */

  /**
   * Signs an operation with a session key
   */
  async signOperationWithSessionKey(
    sessionKeyWallet: ethers.Wallet,
    target: string,
    callData: string,
    accountAddress: string,
    options?: {
      nonce?: bigint;
      deadline?: bigint;
      deadlineSeconds?: number;
    }
  ): Promise<{ signedOperation: SignedOperation; signature: string }> {
    const account: Account = { addr: accountAddress, isPartyB: false };
    
    const replayHeader = createReplayHeader({
      nonce: options?.nonce,
      deadline: options?.deadline,
      deadlineSeconds: options?.deadlineSeconds ?? 300, // 5 min default
    });

    return signOperation(sessionKeyWallet, this.domain, {
      target,
      callData,
      signerAccount: account,
      replayAttackHeader: replayHeader,
    });
  }

  /**
   * Executes a batch of signed operations
   * Must be called by an address with OPERATOR_ROLE
   */
  async executeBatch(
    operatorSigner: ethers.Signer,
    signedOps: SignedOperation[],
    signatures: string[]
  ): Promise<ethers.TransactionReceipt> {
    if (signedOps.length !== signatures.length) {
      throw new Error('Operations and signatures arrays must have same length');
    }

    const contract = this.contract.connect(operatorSigner);
    const tx = await contract.executeBatch(signedOps, signatures);
    return tx.wait();
  }

  /**
   * Executes a template with signed operations
   */
  async executeTemplate(
    operatorSigner: ethers.Signer,
    templateId: number,
    signedOps: SignedOperation[],
    signatures: string[]
  ): Promise<ethers.TransactionReceipt> {
    const contract = this.contract.connect(operatorSigner);
    const tx = await contract.executeTemplate(templateId, signedOps, signatures);
    return tx.wait();
  }

  /* ═══════════════════════════════════════════════════════════════════════════
   * VIEW FUNCTIONS
   * ═══════════════════════════════════════════════════════════════════════════ */

  /**
   * Checks if a delegation is currently active
   */
  async isDelegationActive(
    delegator: string,
    delegate: string,
    selector: string
  ): Promise<boolean> {
    return this.contract.isDelegationActive(delegator, delegate, selector);
  }

  /**
   * Gets the expiry timestamp of a delegation
   */
  async getDelegationExpiry(
    delegator: string,
    delegate: string,
    selector: string
  ): Promise<bigint> {
    return this.contract.delegations(delegator, delegate, selector);
  }

  /**
   * Gets the current delegation nonce for an account
   */
  async getDelegationNonce(account: string): Promise<bigint> {
    return this.contract.delegationNonces(account);
  }

  /**
   * Gets the current operation nonce for an account
   */
  async getOperationNonce(account: string): Promise<bigint> {
    return this.contract.nonces(account);
  }

  /**
   * Gets the revocation cooldown period
   */
  async getRevocationCooldown(): Promise<bigint> {
    return this.contract.revocationCooldown();
  }

  /**
   * Gets the pending revocation ETA for a delegation
   */
  async getPendingRevocationEta(
    delegator: string,
    delegate: string,
    selector: string
  ): Promise<bigint> {
    return this.contract.pendingRevocationEta(delegator, delegate, selector);
  }

  /**
   * Checks if an operation hash has been used
   */
  async isOperationUsed(hash: string): Promise<boolean> {
    return this.contract.usedOperationHashes(hash);
  }

  /**
   * Gets the domain separator from the contract
   */
  async getDomainSeparator(): Promise<string> {
    return this.contract.domainSeparator();
  }

  /**
   * Computes the hash of an operation (for verification)
   */
  async getOperationHash(operation: SignedOperation): Promise<string> {
    return this.contract.getOperationHash(operation);
  }

  /**
   * Checks if multiple selectors are delegated
   */
  async checkDelegations(
    delegator: string,
    delegate: string,
    selectors: string[]
  ): Promise<Map<string, boolean>> {
    const results = new Map<string, boolean>();
    
    await Promise.all(
      selectors.map(async (selector) => {
        const active = await this.isDelegationActive(delegator, delegate, selector);
        results.set(selector, active);
      })
    );
    
    return results;
  }

  /* ═══════════════════════════════════════════════════════════════════════════
   * UTILITY GETTERS
   * ═══════════════════════════════════════════════════════════════════════════ */

  get instantLayerAddress(): string {
    return this.addresses.instantLayer;
  }

  get symmioAddress(): string {
    return this.addresses.symmio;
  }

  get accountHubAddress(): string | undefined {
    return this.addresses.accountHub;
  }

  get networkChainId(): number {
    return this.chainId;
  }
}

/**
 * Helper to validate an address
 */
export function isValidAddress(address: string): boolean {
  return ethers.isAddress(address);
}
