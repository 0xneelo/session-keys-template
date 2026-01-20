# Gas Sponsor Contract

A meta-transaction relay contract that sponsors gas for session key transactions.

## Overview

Instead of funding each session key with ETH for gas, this contract:
1. Holds a pool of ETH for gas sponsorship
2. Accepts signed messages from whitelisted session keys
3. Executes transactions on their behalf
4. Pays gas from the contract's balance

## How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Session Key   │────▶│   Gas Sponsor   │────▶│  Target Contract│
│  (signs tx)     │     │  (pays gas)     │     │  (receives call)│
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                      ▲
         │                      │
         └──────────────────────┘
              signed message
```

1. **Session key signs** a meta-transaction off-chain
2. **Anyone submits** the signed tx to GasSponsor (can be a relayer)
3. **Contract verifies** signature and executes the call
4. **Contract pays** gas from its ETH balance

## Features

- ✅ Whitelist of allowed session keys
- ✅ Replay protection via nonces
- ✅ Deadline/expiry for transactions
- ✅ Daily gas budget limits per signer
- ✅ Maximum gas per transaction limit
- ✅ Owner can withdraw funds

## Deployment

### Prerequisites

```bash
npm install
```

### Deploy to Sepolia

```bash
# Set environment variables
export PRIVATE_KEY="your-deployer-private-key"
export SEPOLIA_RPC="https://ethereum-sepolia-rpc.publicnode.com"

# Deploy
npx hardhat run scripts/deploy.js --network sepolia
```

### After Deployment

1. **Fund the contract** - Send ETH to the contract address
2. **Add session keys** - Call `addSigner(address)` for each session key
3. **Configure limits** - Optionally adjust `setLimits(maxGas, dailyBudget)`

## Usage

### From the Demo Website

1. Create a session key
2. The website will automatically use the GasSponsor for transactions
3. No ETH needed in the session key!

### Programmatic Usage

```javascript
import { ethers } from 'ethers';

// Session key signs the meta-transaction
const messageHash = await gasSponsor.getMessageHash(
  sessionKeyAddress,
  targetContract,
  value,
  calldata,
  deadline,
  nonce
);

const signature = await sessionKeyWallet.signMessage(
  ethers.getBytes(messageHash)
);

// Anyone can submit (relayer pays gas, gets reimbursed from contract)
await gasSponsor.executeMetaTransaction(
  sessionKeyAddress,
  targetContract,
  value,
  calldata,
  deadline,
  nonce,
  signature
);
```

## Contract Functions

### Admin Functions (Owner Only)

| Function | Description |
|----------|-------------|
| `addSigner(address)` | Whitelist a session key |
| `removeSigner(address)` | Remove a session key |
| `addSigners(address[])` | Batch add session keys |
| `setLimits(maxGas, dailyBudget)` | Configure limits |
| `withdraw(to, amount)` | Withdraw ETH |

### Meta-Transaction Functions

| Function | Description |
|----------|-------------|
| `executeMetaTransaction(...)` | Execute any call with signature |
| `executeTransfer(...)` | Simple ETH transfer with signature |

### View Functions

| Function | Description |
|----------|-------------|
| `nonces(address)` | Get current nonce for signer |
| `isSignerAllowed(address)` | Check if signer is whitelisted |
| `getRemainingBudget(address)` | Get remaining daily gas budget |
| `getMessageHash(...)` | Compute message hash for signing |
| `getTransferHash(...)` | Compute transfer hash for signing |

## Security Considerations

1. **Owner controls whitelist** - Only owner can add/remove signers
2. **Replay protection** - Nonces prevent transaction replay
3. **Deadline enforcement** - Transactions expire after deadline
4. **Budget limits** - Daily gas budget prevents abuse
5. **Reentrancy protection** - Uses OpenZeppelin's ReentrancyGuard

## Gas Costs

- Meta-transaction overhead: ~50,000 gas
- Simple transfer via contract: ~30,000 gas
- Direct transfer (without sponsor): ~21,000 gas

The overhead is the cost of sponsorship - worth it if you don't want to fund session keys!

## License

MIT
