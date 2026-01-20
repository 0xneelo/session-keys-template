/**
 * InstantLayer Integration Example
 * 
 * Demonstrates creating session keys and delegating via InstantLayer
 */

import { ethers } from 'ethers';
import {
  SessionKeyManager,
  InstantLayerClient,
  SCOPE_BUNDLES,
  SYMMIO_SELECTORS,
  encodeFunctionCall,
  createReplayHeader,
} from '../src';

// Example Symmio ABI (partial)
const SYMMIO_ABI = [
  'function sendQuote(address[] partyBsWhiteList, uint256 symbolId, uint8 positionType, uint8 orderType, uint256 price, uint256 quantity, uint256 cva, uint256 lf, uint256 partyAmm, uint256 partyBmm, uint256 maxFundingRate, uint256 deadline, bytes upnlSig) external',
  'function requestToClosePosition(uint256 quoteId, uint256 closePrice, uint256 quantityToClose, uint8 orderType, uint256 deadline) external',
];

async function main() {
  // ========================================
  // 1. Setup
  // ========================================

  console.log('=== InstantLayer Session Keys Demo ===\n');

  // Initialize manager
  const manager = new SessionKeyManager({
    autoCleanup: true,
    requireSecureContext: false, // Allow localhost for demo
  });

  // Subscribe to events
  manager.on((event) => {
    console.log(`[Event] ${event.type}:`, 
      'key' in event ? event.key.address : 
      'txHash' in event ? event.txHash : 
      event.keyId
    );
  });

  // ========================================
  // 2. Create Session Key
  // ========================================

  console.log('\n--- Creating Session Key ---');

  const sessionKey = await manager.create({
    password: 'demo-password-123',
    expiryDuration: 24 * 60 * 60, // 24 hours
    scopes: SCOPE_BUNDLES.TRADING_BASIC,
    accountAddress: '0x1234567890123456789012345678901234567890', // Your Symmio account
    chainId: 42161, // Arbitrum
    label: 'Trading Session',
    isPartyB: false, // PartyA account
  });

  console.log('Session key created:');
  console.log('  ID:', sessionKey.id);
  console.log('  Address:', sessionKey.address);
  console.log('  Expiry:', new Date(sessionKey.expiry * 1000).toISOString());
  console.log('  Scopes:', sessionKey.scopes.length, 'selectors');

  // ========================================
  // 3. Setup InstantLayer Client
  // ========================================

  console.log('\n--- InstantLayer Client Setup ---');

  // In production, use real addresses
  const addresses = {
    symmio: '0xSyimmioContractAddress',
    instantLayer: '0xInstantLayerAddress',
    accountHub: '0xAccountHubAddress',
  };

  // Would normally connect to a real provider
  // const provider = new ethers.BrowserProvider(window.ethereum);
  // const instantLayer = InstantLayerClient.fromAddresses(provider, addresses, 42161);

  console.log('InstantLayer configured for chain:', 42161);
  console.log('Contract:', addresses.instantLayer);

  // ========================================
  // 4. Delegation (Simulated)
  // ========================================

  console.log('\n--- Delegation Process ---');
  console.log('To delegate in production:');
  console.log('');
  console.log('// Option 1: Gasless (owner signs, relayer pays)');
  console.log('await manager.delegateToSessionKeyBySig(');
  console.log('  sessionKey.id,');
  console.log('  ownerWallet,');
  console.log('  instantLayer,');
  console.log('  relayerSigner // optional');
  console.log(');');
  console.log('');
  console.log('// Option 2: Direct (owner pays gas)');
  console.log('await manager.delegateToSessionKeyDirect(');
  console.log('  sessionKey.id,');
  console.log('  ownerSigner,');
  console.log('  instantLayer');
  console.log(');');

  // ========================================
  // 5. Signing Operations
  // ========================================

  console.log('\n--- Signing Operations ---');

  // Unlock the session key
  await manager.unlock(sessionKey.id, 'demo-password-123');
  console.log('Session key unlocked');

  // Example: Encode a sendQuote call
  const callData = encodeFunctionCall(SYMMIO_ABI, 'sendQuote', [
    [], // partyBsWhiteList
    1n, // symbolId
    0,  // positionType (LONG)
    0,  // orderType (LIMIT)
    ethers.parseUnits('50000', 18), // price
    ethers.parseUnits('1', 18),     // quantity
    ethers.parseUnits('100', 18),   // cva
    ethers.parseUnits('50', 18),    // lf
    ethers.parseUnits('10', 18),    // partyAmm
    ethers.parseUnits('10', 18),    // partyBmm
    ethers.parseUnits('0.01', 18),  // maxFundingRate
    Math.floor(Date.now() / 1000) + 3600, // deadline
    '0x', // upnlSig
  ]);

  console.log('Encoded sendQuote callData:', callData.slice(0, 66) + '...');

  // In production, sign with InstantLayer domain
  // const { signedOperation, signature } = await manager.signOperation(
  //   sessionKey.id,
  //   addresses.symmio,
  //   callData,
  //   instantLayer,
  //   { deadlineSeconds: 300 }
  // );

  console.log('\nTo sign and execute:');
  console.log('const { signedOperation, signature } = await manager.signOperation(');
  console.log('  sessionKey.id, symmioAddress, callData, instantLayer');
  console.log(');');
  console.log('await instantLayer.executeBatch(operator, [signedOperation], [signature]);');

  // ========================================
  // 6. Revocation Process
  // ========================================

  console.log('\n--- Revocation Process ---');
  console.log('InstantLayer uses two-step revocation with cooldown:');
  console.log('');
  console.log('// Step 1: Initiate (starts cooldown timer)');
  console.log('await manager.initiateRevokeDelegation(sessionKey.id, signer, instantLayer);');
  console.log('');
  console.log('// Wait for cooldown (typically 10 minutes)');
  console.log('const cooldown = await instantLayer.getRevocationCooldown();');
  console.log('');
  console.log('// Step 2: Finalize (after cooldown)');
  console.log('await manager.finalizeRevokeDelegation(sessionKey.id, signer, instantLayer);');

  // ========================================
  // 7. Cleanup
  // ========================================

  console.log('\n--- Cleanup ---');

  // Lock the key
  manager.lock(sessionKey.id);
  console.log('Session key locked');

  // Delete when done
  await manager.delete(sessionKey.id);
  console.log('Session key deleted');

  console.log('\n=== Demo Complete ===');
}

// ========================================
// Advanced: Batch Operations Example
// ========================================

async function batchOperationsExample() {
  console.log('\n=== Batch Operations Example ===');
  
  // In production, you would:
  // 1. Create multiple signed operations
  // 2. Submit them all in one transaction
  
  console.log(`
// Sign multiple operations
const ops = [];
const sigs = [];

for (const trade of trades) {
  const { signedOperation, signature } = await manager.signOperation(
    sessionKey.id,
    symmioAddress,
    encodeTradeCall(trade),
    instantLayer
  );
  ops.push(signedOperation);
  sigs.push(signature);
}

// Execute all atomically
await instantLayer.executeBatch(operator, ops, sigs);
`);
}

// ========================================
// Advanced: Template Operations
// ========================================

async function templateExample() {
  console.log('\n=== Template Operations Example ===');
  
  console.log(`
Templates allow chaining operation results:

// Template defined on-chain:
// - Operation 0: allocate() -> returns amount
// - Operation 1: sendQuote(amount from op 0)

// Sign operations for template
const { signedOperation: allocateOp, signature: sig1 } = await manager.signOperation(...);
const { signedOperation: quoteOp, signature: sig2 } = await manager.signOperation(...);

// Execute template (results chain automatically)
await instantLayer.executeTemplate(
  templateId,
  [allocateOp, quoteOp],
  [sig1, sig2]
);
`);
}

// Run
main().catch(console.error);
