# @symmio/session-keys

A browser-based session key management library for the Symmio Protocol. Generate, store, and manage temporary private keys that can be delegated access via Symmio's **InstantLayer** contract using EIP-712 signatures.

## Features

- 🔐 **Audited Cryptography** - Uses [@noble/curves](https://github.com/paulmillr/noble-curves) and [@scure/bip39](https://github.com/paulmillr/scure-bip39) (audited by Cure53)
- 🛡️ **Constant-Time Operations** - Prevents timing attacks on key operations
- 💾 **Encrypted Local Storage** - Private keys encrypted with AES-256-GCM + PBKDF2, stored in IndexedDB
- ⏱️ **Expiring Keys** - Built-in expiration handling with automatic cleanup
- 🔑 **Scoped Permissions** - Delegate only specific function selectors
- 📝 **EIP-712 Signing** - Full support for InstantLayer's typed data signatures
- 🔗 **InstantLayer Integration** - Direct integration with Symmio's advanced delegation system
- 🪪 **SIWE Authentication** - Sign-In With Ethereum support for solver authentication
- ⛽ **Gasless Delegation** - Owner signs, anyone can submit the delegation tx
- 🌱 **BIP-39/BIP-32 Support** - Optional mnemonic phrase and HD key derivation

## Installation

```bash
npm install @symmio/session-keys ethers siwe
```

## Quick Start

```typescript
import { 
  SessionKeyManager, 
  InstantLayerClient,
  SCOPE_BUNDLES 
} from '@symmio/session-keys';
import { ethers } from 'ethers';

// Initialize the manager
const manager = new SessionKeyManager();

// Create a new session key
const sessionKey = await manager.create({
  password: 'your-secure-password',
  expiryDuration: 86400, // 24 hours in seconds
  scopes: SCOPE_BUNDLES.TRADING_BASIC,
  accountAddress: '0xYourAccountAddress',
  chainId: 42161, // Arbitrum
  label: 'Trading Session',
});

console.log('Session key created:', sessionKey.address);
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     USER / DAPP                             │
├─────────────────────────────────────────────────────────────┤
│  SessionKeyManager                                          │
│  ├── Create/Store encrypted session keys                    │
│  ├── Sign operations with EIP-712                           │
│  └── Manage delegation lifecycle                            │
├─────────────────────────────────────────────────────────────┤
│  InstantLayer Contract (On-Chain)                           │
│  ├── Delegation via signature (grantBatchDelegationBySig)   │
│  ├── Two-step revocation with cooldown                      │
│  ├── Batch operation execution                              │
│  └── Template-based operation sequences                     │
├─────────────────────────────────────────────────────────────┤
│  Symmio Protocol                                            │
│  └── Trading, allocation, liquidation functions             │
└─────────────────────────────────────────────────────────────┘
```

## Usage Guide

### Creating Session Keys

```typescript
import { SessionKeyManager, SYMMIO_SELECTORS } from '@symmio/session-keys';

const manager = new SessionKeyManager();

// Create with custom scopes
const key = await manager.create({
  password: 'minimum-8-chars',
  expiryDuration: 3600, // 1 hour
  scopes: [
    SYMMIO_SELECTORS.SEND_QUOTE,
    SYMMIO_SELECTORS.REQUEST_TO_CLOSE_POSITION,
  ],
  accountAddress: '0x...',
  chainId: 42161,
});
```

### Using Predefined Scope Bundles

```typescript
import { SCOPE_BUNDLES } from '@symmio/session-keys';

// Available bundles:
SCOPE_BUNDLES.TRADING_BASIC    // Open/close positions
SCOPE_BUNDLES.TRADING_FULL     // All trading operations
SCOPE_BUNDLES.ACCOUNT_MANAGEMENT // Allocate/deallocate
SCOPE_BUNDLES.FULL_ACCESS      // Everything
```

### Direct Key Generation (Advanced)

For advanced use cases, you can use the crypto primitives directly:

```typescript
import {
  generatePrivateKey,
  getAddress,
  generateWalletWithMnemonic,
  deriveKeyFromMnemonic,
  isValidMnemonic,
} from '@symmio/session-keys';

// Generate a random private key (uses @noble/curves)
const privateKey = generatePrivateKey();
const address = getAddress(privateKey);

// Generate with mnemonic backup (uses @scure/bip39)
const { mnemonic, privateKey: pk, address: addr } = generateWalletWithMnemonic();
console.log('Backup phrase:', mnemonic); // 12 words

// Recover from mnemonic
const recoveredKey = deriveKeyFromMnemonic(mnemonic);

// Validate mnemonic
if (isValidMnemonic(userInput)) {
  const key = deriveKeyFromMnemonic(userInput);
}
```

### Delegating via InstantLayer

There are two ways to delegate access to a session key:

#### 1. Gasless Delegation (Owner Signs, Anyone Submits)

```typescript
import { InstantLayerClient } from '@symmio/session-keys';

// Create InstantLayer client
const instantLayer = InstantLayerClient.fromAddresses(
  provider,
  {
    symmio: '0x...',
    instantLayer: '0x...',
    accountHub: '0x...',
  },
  42161 // chainId
);

// Owner signs the delegation, tx can be submitted by anyone
const receipt = await manager.delegateToSessionKeyBySig(
  sessionKey.id,
  ownerWallet,      // Signs the delegation
  instantLayer,
  relayerSigner     // Optional: different signer pays gas
);
```

#### 2. Direct Delegation (Owner Submits)

```typescript
// Owner submits the transaction directly
const receipt = await manager.delegateToSessionKeyDirect(
  sessionKey.id,
  ownerSigner,
  instantLayer
);
```

### Signing Operations

```typescript
// Unlock the session key
await manager.unlock(sessionKey.id, 'your-password');

// Sign an operation for execution via InstantLayer
const { signedOperation, signature } = await manager.signOperation(
  sessionKey.id,
  symmioAddress,  // target contract
  callData,       // encoded function call
  instantLayer,
  {
    deadlineSeconds: 300, // 5 minute deadline
  }
);

// Operations are executed by an operator with OPERATOR_ROLE
await instantLayer.executeBatch(operatorSigner, [signedOperation], [signature]);
```

### Encoding Function Calls

```typescript
import { encodeFunctionCall } from '@symmio/session-keys';

// Encode a sendQuote call
const callData = encodeFunctionCall(
  SYMMIO_ABI,
  'sendQuote',
  [partyBsWhiteList, symbolId, positionType, orderType, price, quantity, ...]
);
```

### Revoking Delegation

InstantLayer uses a two-step revocation process with a cooldown period:

```typescript
// Step 1: Initiate revocation (starts cooldown)
await manager.initiateRevokeDelegation(
  sessionKey.id,
  signer, // owner, delegate, or REVOKER_ROLE
  instantLayer
);

// Check cooldown
const cooldown = await instantLayer.getRevocationCooldown();
console.log(`Wait ${cooldown} seconds before finalizing`);

// Step 2: Finalize revocation (after cooldown)
await manager.finalizeRevokeDelegation(
  sessionKey.id,
  signer,
  instantLayer
);
```

### Checking Delegation Status

```typescript
// Check if session key delegation is active
const isActive = await manager.isDelegationActive(sessionKey.id, instantLayer);

// Check specific selectors
const delegations = await instantLayer.checkDelegations(
  accountAddress,
  sessionKey.address,
  SCOPE_BUNDLES.TRADING_BASIC
);

for (const [selector, active] of delegations) {
  console.log(`${selector}: ${active ? 'delegated' : 'not delegated'}`);
}
```

### Event Handling

```typescript
// Subscribe to events
const unsubscribe = manager.on((event) => {
  switch (event.type) {
    case 'created':
      console.log('Key created:', event.key.address);
      break;
    case 'delegated':
      console.log('Delegated in tx:', event.txHash);
      break;
    case 'expired':
      console.log('Key expired:', event.keyId);
      break;
  }
});

// Unsubscribe when done
unsubscribe();
```

### SIWE Authentication

```typescript
import { SiweAuthClient } from '@symmio/session-keys';

const authClient = new SiweAuthClient({
  baseUrl: 'https://solver.symm.io',
  chainId: 42161,
});

// Unlock session key first
await manager.unlock(sessionKey.id, 'password');

// Authenticate and get access token
const { accessToken } = await manager.authenticate(sessionKey.id, authClient);

// Use token for API calls
fetch('https://solver.symm.io/api/trade', {
  headers: { Authorization: `Bearer ${accessToken}` },
});
```

## API Reference

### SessionKeyManager

| Method | Description |
|--------|-------------|
| `create(options)` | Creates a new encrypted session key |
| `unlock(keyId, password)` | Decrypts and loads key into memory |
| `lock(keyId)` | Removes key from memory |
| `signMessage(keyId, message)` | Signs a message |
| `signTypedData(keyId, ...)` | Signs EIP-712 typed data |
| `signOperation(keyId, ...)` | Signs an InstantLayer operation |
| `delegateToSessionKeyBySig(...)` | Gasless delegation via signature |
| `delegateToSessionKeyDirect(...)` | Direct delegation (owner submits) |
| `initiateRevokeDelegation(...)` | Start revocation cooldown |
| `finalizeRevokeDelegation(...)` | Complete revocation |
| `isDelegationActive(...)` | Check if delegation is active |

### InstantLayerClient

| Method | Description |
|--------|-------------|
| `fromAddresses(provider, addresses, chainId)` | Create client |
| `grantDelegationBySig(...)` | Grant delegation via signature |
| `grantDelegationDirect(...)` | Grant delegation directly |
| `initiateRevokeDelegation(...)` | Start revocation |
| `finalizeRevokeDelegation(...)` | Finalize revocation |
| `executeBatch(...)` | Execute batch of operations |
| `executeTemplate(...)` | Execute template operations |
| `isDelegationActive(...)` | Check delegation status |
| `getDelegationNonce(account)` | Get delegation nonce |
| `getRevocationCooldown()` | Get cooldown period |

### EIP-712 Utilities

| Function | Description |
|----------|-------------|
| `signDelegation(wallet, domain, info, header)` | Sign a delegation |
| `signOperation(wallet, domain, op)` | Sign an operation |
| `createReplayHeader(options)` | Create anti-replay header |
| `generateSalt()` | Generate random salt |
| `computeSelector(signature)` | Compute function selector |

### Function Selectors

```typescript
import { SYMMIO_SELECTORS } from '@symmio/session-keys';

// Trading
SYMMIO_SELECTORS.SEND_QUOTE
SYMMIO_SELECTORS.REQUEST_TO_CLOSE_POSITION
SYMMIO_SELECTORS.REQUEST_TO_CANCEL_QUOTE
// ... more

// Account
SYMMIO_SELECTORS.ALLOCATE
SYMMIO_SELECTORS.DEALLOCATE
// ... more
```

## Security Considerations

1. **Password Strength**: Use strong passwords (8+ characters minimum, recommended 12+)
2. **Secure Context**: Use HTTPS in production (required for Web Crypto API)
3. **Expiration**: Set reasonable expiry times (hours, not days)
4. **Scope Limitation**: Only delegate necessary function selectors
5. **Revocation Cooldown**: Be aware of the cooldown period before revocation completes
6. **Key Cleanup**: Regularly cleanup expired keys
7. **Memory Security**: Lock keys when not in use

### Cryptographic Libraries Used

This library uses **audited, zero-dependency** cryptographic libraries:

| Library | Purpose | Audit |
|---------|---------|-------|
| [@noble/curves](https://github.com/paulmillr/noble-curves) | secp256k1 key generation & signing | Cure53 |
| [@noble/hashes](https://github.com/paulmillr/noble-hashes) | SHA-256, Keccak-256, PBKDF2 | Cure53 |
| [@scure/bip39](https://github.com/paulmillr/scure-bip39) | Mnemonic phrase generation | Cure53 |
| [@scure/bip32](https://github.com/paulmillr/scure-bip32) | HD key derivation | Cure53 |
| Web Crypto API | AES-256-GCM encryption | Browser native |

All `@noble` and `@scure` libraries:
- Have **zero dependencies**
- Use **constant-time** operations to prevent timing attacks
- Are **audited** by Cure53
- Are used by major projects (Ethereum Foundation, MetaMask, etc.)

## InstantLayer Contract Features

The library integrates with Symmio's InstantLayer contract which provides:

- **Flexible Nonce Management**: Salt-only (nonce=0) or ordered execution (nonce>0)
- **Deadline Enforcement**: Time-sensitive operation expiry
- **Batch Processing**: Execute multiple operations atomically
- **Template Operations**: Pre-defined sequences with result chaining
- **Role-Based Access**: OPERATOR_ROLE required for execution
- **Two-Step Revocation**: Cooldown period protects against immediate revocation

## Browser Compatibility

Requires modern browsers with:
- Web Crypto API
- IndexedDB (falls back to localStorage)
- ES2020 support

Tested on:
- Chrome 90+
- Firefox 90+
- Safari 15+
- Edge 90+

## License

MIT
