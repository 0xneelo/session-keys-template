# Session Keys Demo

A test website demonstrating the Symmio Session Keys library.

## Features

- 🔐 Create encrypted session keys stored in browser (localStorage)
- 🔓 Unlock keys with password to enable signing
- ✍️ Sign arbitrary messages
- 📤 Send testnet ETH transactions
- 🌐 Connected to Sepolia testnet

## Running the Demo

```bash
cd demo
npx serve
```

Then open http://localhost:3000 in your browser.

## How to Use

### Step 1: Create a Session Key

1. Enter a password (minimum 8 characters)
2. Select expiry duration
3. Optionally enable mnemonic backup
4. Click "Create Session Key"

If you enabled mnemonic, **write down the 12-word phrase** - it won't be shown again!

### Step 2: Get Testnet ETH

Use one of the faucet links to get Sepolia testnet ETH:
- [Sepolia Faucet](https://sepoliafaucet.com/)
- [Alchemy Faucet](https://www.alchemy.com/faucets/ethereum-sepolia)
- [Google Cloud Faucet](https://cloud.google.com/application/web3/faucet/ethereum/sepolia)

Copy your session key address and paste it into the faucet.

### Step 3: Sign a Message

1. Unlock your session key with your password
2. Enter a message to sign
3. Click "Sign Message"

The signature will be displayed below - this proves you control the session key.

### Step 4: Send a Transaction

1. Make sure your session key is unlocked
2. Enter the amount of ETH to send
3. Click "Send Transaction"

The transaction will be sent to `0x83B285E802D76055169B1C5e3bF21702B85b89Cb` on Sepolia.

## Technical Details

- **Network**: Sepolia Testnet (Chain ID: 11155111)
- **RPC**: https://ethereum-sepolia-rpc.publicnode.com
- **Explorer**: https://sepolia.etherscan.io

### Encryption

- **Algorithm**: AES-256-GCM
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Storage**: Browser localStorage (encrypted)

### Security Notes

- Private keys are encrypted at rest with your password
- Keys are only decrypted when you unlock them
- Unlocked keys are held in memory only
- Session keys expire after the configured duration
- Closing the browser tab clears the unlocked key from memory

## Recipient Address

All demo transactions are sent to:
```
0x83B285E802D76055169B1C5e3bF21702B85b89Cb
```
