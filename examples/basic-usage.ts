/**
 * Basic Usage Example
 * Demonstrates creating, delegating, and using session keys
 */

import { ethers } from 'ethers';
import {
  SessionKeyManager,
  SymmioClient,
  SiweAuthClient,
  SCOPE_BUNDLES,
  SYMMIO_SELECTORS,
} from '../src';

async function main() {
  // ========================================
  // 1. Initialize the Session Key Manager
  // ========================================
  
  const manager = new SessionKeyManager({
    autoCleanup: true,
    requireSecureContext: false, // Set to true in production
  });

  // Listen for events
  manager.on((event) => {
    console.log('Session Key Event:', event);
  });

  // ========================================
  // 2. Create a Session Key
  // ========================================

  console.log('\n--- Creating Session Key ---');

  const sessionKey = await manager.create({
    password: 'my-secure-password-123',
    expiryDuration: 24 * 60 * 60, // 24 hours
    scopes: SCOPE_BUNDLES.TRADING_BASIC,
    subAccountAddress: '0x1234567890123456789012345678901234567890',
    chainId: 42161, // Arbitrum
    label: 'Trading Bot Session',
  });

  console.log('Created session key:');
  console.log('  ID:', sessionKey.id);
  console.log('  Address:', sessionKey.address);
  console.log('  Expiry:', new Date(sessionKey.expiry * 1000).toISOString());
  console.log('  Scopes:', sessionKey.scopes);

  // ========================================
  // 3. Unlock and Sign
  // ========================================

  console.log('\n--- Unlocking and Signing ---');

  // Unlock the key
  const unlocked = await manager.unlock(sessionKey.id, 'my-secure-password-123');
  console.log('Key unlocked:', unlocked.address);

  // Sign a message
  const message = 'Hello, Symmio!';
  const signature = await manager.signMessage(sessionKey.id, message);
  console.log('Signed message:', signature.slice(0, 20) + '...');

  // Get a wallet instance
  const wallet = manager.getWallet(sessionKey.id);
  console.log('Wallet address:', wallet.address);

  // ========================================
  // 4. Delegate On-Chain (requires provider)
  // ========================================

  console.log('\n--- On-Chain Delegation (simulated) ---');

  // In a real app, you'd connect to a provider
  // const provider = new ethers.BrowserProvider(window.ethereum);
  // const ownerSigner = await provider.getSigner();
  // const symmio = SymmioClient.fromNetwork(42161, ownerSigner);
  // await manager.delegateToSessionKey(sessionKey.id, ownerSigner, symmio);

  console.log('Delegation would call MultiAccount.delegateAccesses with:');
  console.log('  Sub-account:', sessionKey.subAccountAddress);
  console.log('  Target (session key):', sessionKey.address);
  console.log('  Selectors:', sessionKey.scopes);

  // ========================================
  // 5. SIWE Authentication (requires backend)
  // ========================================

  console.log('\n--- SIWE Authentication (simulated) ---');

  // In a real app, you'd authenticate with a solver
  // const authClient = new SiweAuthClient({
  //   baseUrl: 'https://solver.symm.io',
  //   chainId: 42161,
  // });
  // const { accessToken } = await manager.authenticate(sessionKey.id, authClient);

  console.log('SIWE auth would:');
  console.log('  1. Fetch nonce from solver');
  console.log('  2. Build SIWE message');
  console.log('  3. Sign with session key');
  console.log('  4. Exchange for access token');

  // ========================================
  // 6. Key Management
  // ========================================

  console.log('\n--- Key Management ---');

  // List all keys
  const allKeys = await manager.list();
  console.log('Total keys:', allKeys.length);

  // Check validity
  const isValid = await manager.isValid(sessionKey.id);
  console.log('Is valid:', isValid);

  // Time remaining
  const remaining = await manager.getTimeRemaining(sessionKey.id);
  console.log('Time remaining:', remaining, 'seconds');

  // Update label
  await manager.updateLabel(sessionKey.id, 'Updated Label');
  const updated = await manager.get(sessionKey.id);
  console.log('Updated label:', updated?.label);

  // Lock the key
  manager.lock(sessionKey.id);
  console.log('Key locked');

  // Check unlock status
  console.log('Is unlocked:', manager.isUnlocked(sessionKey.id));

  // ========================================
  // 7. Cleanup
  // ========================================

  console.log('\n--- Cleanup ---');

  // Delete the session key
  await manager.delete(sessionKey.id);
  console.log('Session key deleted');

  // Verify deletion
  const deleted = await manager.get(sessionKey.id);
  console.log('Key exists after delete:', deleted !== null);
}

// ========================================
// Advanced: Custom Scopes Example
// ========================================

async function advancedExample() {
  const manager = new SessionKeyManager();

  // Create a key with specific custom scopes
  const key = await manager.create({
    password: 'secure-password',
    expiryDuration: 3600, // 1 hour - short lived for security
    scopes: [
      SYMMIO_SELECTORS.SEND_QUOTE,
      SYMMIO_SELECTORS.REQUEST_TO_CLOSE_POSITION,
      // Only allow opening and closing - no allocation/deallocation
    ],
    subAccountAddress: '0x...',
    chainId: 42161,
  });

  console.log('Created limited-scope key:', key.address);
}

// ========================================
// Advanced: Multiple Keys Example
// ========================================

async function multipleKeysExample() {
  const manager = new SessionKeyManager();

  // Create separate keys for different purposes
  const tradingKey = await manager.create({
    password: 'trading-password',
    expiryDuration: 86400,
    scopes: SCOPE_BUNDLES.TRADING_FULL,
    label: 'Trading Operations',
    chainId: 42161,
  });

  const accountKey = await manager.create({
    password: 'account-password',
    expiryDuration: 3600, // Shorter expiry for sensitive operations
    scopes: SCOPE_BUNDLES.ACCOUNT_MANAGEMENT,
    label: 'Account Management',
    chainId: 42161,
  });

  console.log('Trading key:', tradingKey.address);
  console.log('Account key:', accountKey.address);

  // List valid keys
  const keys = await manager.listValid();
  console.log('Valid keys:', keys.map(k => k.label));
}

// Run the example
main().catch(console.error);
