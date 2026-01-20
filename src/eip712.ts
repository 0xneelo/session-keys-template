/**
 * EIP-712 Signing Utilities for Symmio InstantLayer
 * 
 * Implements the typed data signing as required by the InstantLayer contract
 * for operations and delegations.
 */

import { ethers } from 'ethers';
import type {
  Account,
  ReplayAttackHeader,
  SignedOperation,
  SignedDelegation,
  DelegationInfo,
  InstantLayerDomain,
} from './types';

/**
 * EIP-712 Type definitions for InstantLayer
 */
export const EIP712_TYPES = {
  Account: [
    { name: 'addr', type: 'address' },
    { name: 'isPartyB', type: 'bool' },
  ],
  ReplayAttackHeader: [
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
    { name: 'salt', type: 'bytes32' },
  ],
  SignedOperation: [
    { name: 'signer', type: 'address' },
    { name: 'target', type: 'address' },
    { name: 'callData', type: 'bytes' },
    { name: 'signerAccount', type: 'Account' },
    { name: 'replayAttackHeader', type: 'ReplayAttackHeader' },
  ],
  DelegationInfo: [
    { name: 'account', type: 'Account' },
    { name: 'delegatedSigner', type: 'address' },
    { name: 'selectors', type: 'bytes4[]' },
    { name: 'expiryTimestamp', type: 'uint256' },
  ],
  SignedDelegation: [
    { name: 'delegationInfo', type: 'DelegationInfo' },
    { name: 'replayAttackHeader', type: 'ReplayAttackHeader' },
  ],
};

/**
 * Creates the EIP-712 domain for InstantLayer
 */
export function createInstantLayerDomain(
  chainId: number,
  verifyingContract: string
): InstantLayerDomain {
  return {
    name: 'SymmioInstantLayer',
    version: '1',
    chainId,
    verifyingContract,
  };
}

/**
 * Generates a random salt for replay protection
 */
export function generateSalt(): string {
  const bytes = ethers.randomBytes(32);
  return ethers.hexlify(bytes);
}

/**
 * Creates a ReplayAttackHeader with sensible defaults
 */
export function createReplayHeader(options: {
  nonce?: bigint;
  deadline?: bigint;
  salt?: string;
  deadlineSeconds?: number;
}): ReplayAttackHeader {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const defaultDeadline = options.deadlineSeconds 
    ? now + BigInt(options.deadlineSeconds)
    : 0n; // 0 means no deadline

  return {
    nonce: options.nonce ?? 0n, // 0 = salt-only replay protection
    deadline: options.deadline ?? defaultDeadline,
    salt: options.salt ?? generateSalt(),
  };
}

/**
 * Signs a delegation using EIP-712
 */
export async function signDelegation(
  wallet: ethers.Wallet,
  domain: InstantLayerDomain,
  delegationInfo: DelegationInfo,
  replayHeader: ReplayAttackHeader
): Promise<{ signedDelegation: SignedDelegation; signature: string }> {
  const signedDelegation: SignedDelegation = {
    delegationInfo,
    replayAttackHeader: replayHeader,
  };

  // Prepare the typed data value
  const value = {
    delegationInfo: {
      account: {
        addr: delegationInfo.account.addr,
        isPartyB: delegationInfo.account.isPartyB,
      },
      delegatedSigner: delegationInfo.delegatedSigner,
      selectors: delegationInfo.selectors,
      expiryTimestamp: delegationInfo.expiryTimestamp,
    },
    replayAttackHeader: {
      nonce: replayHeader.nonce,
      deadline: replayHeader.deadline,
      salt: replayHeader.salt,
    },
  };

  // Define types for signing (excluding EIP712Domain)
  const types = {
    Account: EIP712_TYPES.Account,
    ReplayAttackHeader: EIP712_TYPES.ReplayAttackHeader,
    DelegationInfo: EIP712_TYPES.DelegationInfo,
    SignedDelegation: EIP712_TYPES.SignedDelegation,
  };

  const signature = await wallet.signTypedData(domain, types, value);

  return { signedDelegation, signature };
}

/**
 * Signs an operation using EIP-712
 */
export async function signOperation(
  wallet: ethers.Wallet,
  domain: InstantLayerDomain,
  operation: Omit<SignedOperation, 'signer'>,
  signer?: string
): Promise<{ signedOperation: SignedOperation; signature: string }> {
  const signerAddress = signer ?? wallet.address;

  const signedOperation: SignedOperation = {
    signer: signerAddress,
    target: operation.target,
    callData: operation.callData,
    signerAccount: operation.signerAccount,
    replayAttackHeader: operation.replayAttackHeader,
  };

  // Prepare the typed data value
  const value = {
    signer: signerAddress,
    target: operation.target,
    callData: operation.callData,
    signerAccount: {
      addr: operation.signerAccount.addr,
      isPartyB: operation.signerAccount.isPartyB,
    },
    replayAttackHeader: {
      nonce: operation.replayAttackHeader.nonce,
      deadline: operation.replayAttackHeader.deadline,
      salt: operation.replayAttackHeader.salt,
    },
  };

  // Define types for signing
  const types = {
    Account: EIP712_TYPES.Account,
    ReplayAttackHeader: EIP712_TYPES.ReplayAttackHeader,
    SignedOperation: EIP712_TYPES.SignedOperation,
  };

  const signature = await wallet.signTypedData(domain, types, value);

  return { signedOperation, signature };
}

/**
 * Creates a SignedOperation structure ready for signing
 */
export function createOperation(params: {
  signer: string;
  target: string;
  callData: string;
  account: Account;
  nonce?: bigint;
  deadline?: bigint;
  deadlineSeconds?: number;
  salt?: string;
}): SignedOperation {
  return {
    signer: params.signer,
    target: params.target,
    callData: params.callData,
    signerAccount: params.account,
    replayAttackHeader: createReplayHeader({
      nonce: params.nonce,
      deadline: params.deadline,
      deadlineSeconds: params.deadlineSeconds,
      salt: params.salt,
    }),
  };
}

/**
 * Creates a DelegationInfo structure
 */
export function createDelegationInfo(params: {
  accountAddress: string;
  isPartyB?: boolean;
  delegatedSigner: string;
  selectors: string[];
  expiryTimestamp: bigint;
}): DelegationInfo {
  return {
    account: {
      addr: params.accountAddress,
      isPartyB: params.isPartyB ?? false,
    },
    delegatedSigner: params.delegatedSigner,
    selectors: params.selectors,
    expiryTimestamp: params.expiryTimestamp,
  };
}

/**
 * Encodes a function call for use in operations
 */
export function encodeFunctionCall(
  abi: ethers.InterfaceAbi,
  functionName: string,
  args: unknown[]
): string {
  const iface = new ethers.Interface(abi);
  return iface.encodeFunctionData(functionName, args);
}

/**
 * Decodes a function result
 */
export function decodeFunctionResult(
  abi: ethers.InterfaceAbi,
  functionName: string,
  data: string
): ethers.Result {
  const iface = new ethers.Interface(abi);
  return iface.decodeFunctionResult(functionName, data);
}

/**
 * Computes a function selector from its signature
 */
export function computeSelector(functionSignature: string): string {
  return ethers.id(functionSignature).slice(0, 10);
}

/**
 * Validates that a selector is properly formatted (0x + 8 hex chars)
 */
export function isValidSelector(selector: string): boolean {
  return /^0x[0-9a-fA-F]{8}$/.test(selector);
}

/**
 * Normalizes selectors to proper format
 */
export function normalizeSelectors(selectors: string[]): string[] {
  return selectors.map((sel) => {
    // If already a valid selector, return as-is
    if (isValidSelector(sel)) {
      return sel.toLowerCase();
    }
    // If it looks like a function signature, compute the selector
    if (sel.includes('(')) {
      return computeSelector(sel);
    }
    throw new Error(`Invalid selector format: ${sel}`);
  });
}
