/**
 * SIWE (Sign-In With Ethereum) Authentication Flow
 * For obtaining access tokens from Symmio solvers
 */

import { ethers } from 'ethers';
import { SiweMessage } from 'siwe';
import type { AuthTokenResponse, SiweParams, UnlockedSessionKey } from './types';

/**
 * Default SIWE configuration
 */
const DEFAULT_SIWE_CONFIG = {
  version: '1',
  statement: 'Sign in to Symmio with your session key',
};

/**
 * Builds a SIWE message for authentication
 */
export function buildSiweMessage(params: SiweParams): SiweMessage {
  const message = new SiweMessage({
    domain: params.domain,
    address: params.address,
    statement: params.statement || DEFAULT_SIWE_CONFIG.statement,
    uri: params.uri,
    version: params.version || DEFAULT_SIWE_CONFIG.version,
    chainId: params.chainId,
    nonce: params.nonce,
    issuedAt: params.issuedAt || new Date().toISOString(),
    expirationTime: params.expirationTime,
    notBefore: params.notBefore,
    requestId: params.requestId,
    resources: params.resources,
  });

  return message;
}

/**
 * Signs a SIWE message with a session key
 */
export async function signSiweMessage(
  message: SiweMessage,
  privateKey: string
): Promise<string> {
  const wallet = new ethers.Wallet(privateKey);
  const messageString = message.prepareMessage();
  return wallet.signMessage(messageString);
}

/**
 * SIWE Authentication Client
 */
export class SiweAuthClient {
  private baseUrl: string;
  private domain: string;
  private chainId: number;

  constructor(options: {
    baseUrl: string;
    domain?: string;
    chainId: number;
  }) {
    this.baseUrl = options.baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this.domain = options.domain || new URL(options.baseUrl).hostname;
    this.chainId = options.chainId;
  }

  /**
   * Fetches a nonce from the authentication server
   */
  async fetchNonce(address: string): Promise<string> {
    const response = await fetch(`${this.baseUrl}/auth/nonce`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address }),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch nonce: ${response.statusText}`);
    }

    const data = await response.json();
    return data.nonce;
  }

  /**
   * Authenticates with a session key and returns an access token
   */
  async authenticate(
    sessionKey: UnlockedSessionKey,
    options?: {
      statement?: string;
      expirySeconds?: number;
      resources?: string[];
    }
  ): Promise<AuthTokenResponse> {
    // Validate session key is not expired
    if (sessionKey.expiry * 1000 < Date.now()) {
      throw new Error('Session key has expired');
    }

    // Fetch nonce
    const nonce = await this.fetchNonce(sessionKey.address);

    // Calculate expiration time
    const expirySeconds = options?.expirySeconds || 3600; // Default 1 hour
    const expirationTime = new Date(
      Math.min(
        Date.now() + expirySeconds * 1000,
        sessionKey.expiry * 1000 // Don't exceed session key expiry
      )
    ).toISOString();

    // Build SIWE message
    const message = buildSiweMessage({
      domain: this.domain,
      address: sessionKey.address,
      statement: options?.statement || `Login for account ${sessionKey.accountAddress || 'unknown'}`,
      uri: this.baseUrl,
      chainId: this.chainId,
      nonce,
      expirationTime,
      resources: options?.resources,
    });

    // Sign the message
    const signature = await signSiweMessage(message, sessionKey.privateKey);

    // Send to server
    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: message.prepareMessage(),
        signature,
        accountAddress: sessionKey.accountAddress,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Authentication failed: ${error}`);
    }

    const data = await response.json();
    return {
      accessToken: data.accessToken,
      expiresAt: new Date(expirationTime).getTime(),
      accountAddress: sessionKey.accountAddress || '',
    };
  }

  /**
   * Refreshes an access token (if supported by the server)
   */
  async refreshToken(accessToken: string): Promise<AuthTokenResponse> {
    const response = await fetch(`${this.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to refresh token: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Logs out / invalidates the access token
   */
  async logout(accessToken: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/auth/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to logout: ${response.statusText}`);
    }
  }
}

/**
 * Creates a standalone SIWE message for custom authentication flows
 */
export function createSiweMessage(options: {
  address: string;
  domain: string;
  uri: string;
  chainId: number;
  nonce: string;
  statement?: string;
  expirationTime?: Date;
  notBefore?: Date;
  requestId?: string;
  resources?: string[];
}): SiweMessage {
  return buildSiweMessage({
    address: options.address,
    domain: options.domain,
    uri: options.uri,
    chainId: options.chainId,
    nonce: options.nonce,
    statement: options.statement,
    expirationTime: options.expirationTime?.toISOString(),
    notBefore: options.notBefore?.toISOString(),
    requestId: options.requestId,
    resources: options.resources,
  });
}

/**
 * Generates a random nonce for SIWE messages
 */
export function generateNonce(length: number = 16): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verifies a SIWE message signature (for server-side use)
 */
export async function verifySiweSignature(
  message: string,
  signature: string,
  expectedAddress: string
): Promise<boolean> {
  try {
    const siweMessage = new SiweMessage(message);
    const result = await siweMessage.verify({ signature });
    return result.success && result.data.address.toLowerCase() === expectedAddress.toLowerCase();
  } catch {
    return false;
  }
}
