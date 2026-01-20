/**
 * Symmio Session Keys - Demo Application
 * 
 * This demo shows how to:
 * 1. Create an encrypted session key stored in browser
 * 2. Sign messages with the session key
 * 3. Send transactions on Sepolia testnet
 */

import { ethers } from 'https://cdn.jsdelivr.net/npm/ethers@6.11.0/dist/ethers.min.js';

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

const CONFIG = {
  // Sepolia Testnet
  chainId: 11155111,
  chainName: 'Sepolia',
  rpcUrl: 'https://ethereum-sepolia-rpc.publicnode.com',
  explorerUrl: 'https://sepolia.etherscan.io',
  
  // Target address for sending ETH
  recipientAddress: '0x83B285E802D76055169B1C5e3bF21702B85b89Cb',
  
  // Gas Sponsor contract (deploy your own or use this)
  // Set to null to disable gas sponsorship
  gasSponsorAddress: null, // Update after deploying: '0x...'
  
  // Storage key
  storageKey: 'symmio-session-key',
};

// GasSponsor contract ABI (full)
const GAS_SPONSOR_ABI = [
  'constructor()',
  'function owner() view returns (address)',
  'function deposit() payable',
  'function withdraw()',
  'function addSigner(address signer, uint256 budget)',
  'function removeSigner(address signer)',
  'function isSignerAllowed(address signer) view returns (bool)',
  'function getRemainingBudget(address signer) view returns (uint256)',
  'function signerBudgets(address) view returns (uint256)',
  'function executeTransfer(address signer, address to, uint256 value, uint256 deadline, uint256 nonce, bytes signature) external',
  'function getTransferHash(address signer, address to, uint256 value, uint256 deadline, uint256 nonce) view returns (bytes32)',
  'function nonces(address) view returns (uint256)',
];

// We'll deploy using raw transaction instead of ContractFactory for better compatibility
// This uses CREATE opcode directly

/* ═══════════════════════════════════════════════════════════════════════════
 * State
 * ═══════════════════════════════════════════════════════════════════════════ */

let state = {
  sessionKey: null,      // Stored (encrypted) session key data
  unlockedWallet: null,  // Decrypted wallet instance
  provider: null,        // Ethers provider
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Crypto Utilities
 * ═══════════════════════════════════════════════════════════════════════════ */

const PBKDF2_ITERATIONS = 100000;

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptPrivateKey(privateKey, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const encoder = new TextEncoder();
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(privateKey)
  );

  return {
    encrypted: arrayBufferToBase64(encrypted),
    salt: arrayBufferToBase64(salt.buffer),
    iv: arrayBufferToBase64(iv.buffer),
  };
}

async function decryptPrivateKey(encryptedData, password) {
  const salt = new Uint8Array(base64ToArrayBuffer(encryptedData.salt));
  const iv = new Uint8Array(base64ToArrayBuffer(encryptedData.iv));
  const encrypted = base64ToArrayBuffer(encryptedData.encrypted);

  const key = await deriveKey(password, salt);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    throw new Error('Invalid password');
  }
}

function generateKeyId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Session Key Management
 * ═══════════════════════════════════════════════════════════════════════════ */

async function createSessionKey(password, expirySeconds, withMnemonic = false) {
  let wallet, mnemonic = null;
  
  if (withMnemonic) {
    // Create wallet with mnemonic
    wallet = ethers.Wallet.createRandom();
    mnemonic = wallet.mnemonic.phrase;
  } else {
    // Create wallet without mnemonic (just random key)
    wallet = ethers.Wallet.createRandom();
  }

  const encrypted = await encryptPrivateKey(wallet.privateKey, password);
  
  const now = Math.floor(Date.now() / 1000);
  const sessionKey = {
    id: generateKeyId(),
    address: wallet.address,
    encryptedPrivateKey: encrypted.encrypted,
    salt: encrypted.salt,
    iv: encrypted.iv,
    expiry: now + expirySeconds,
    createdAt: now,
  };

  // Save to localStorage
  localStorage.setItem(CONFIG.storageKey, JSON.stringify(sessionKey));
  
  return { sessionKey, mnemonic };
}

function loadSessionKey() {
  const stored = localStorage.getItem(CONFIG.storageKey);
  if (!stored) return null;
  
  try {
    const sessionKey = JSON.parse(stored);
    
    // Check if expired
    if (sessionKey.expiry * 1000 < Date.now()) {
      localStorage.removeItem(CONFIG.storageKey);
      return null;
    }
    
    return sessionKey;
  } catch (e) {
    return null;
  }
}

async function unlockSessionKey(password) {
  if (!state.sessionKey) {
    throw new Error('No session key found');
  }
  
  const privateKey = await decryptPrivateKey({
    encrypted: state.sessionKey.encryptedPrivateKey,
    salt: state.sessionKey.salt,
    iv: state.sessionKey.iv,
  }, password);
  
  state.unlockedWallet = new ethers.Wallet(privateKey, state.provider);
  return state.unlockedWallet;
}

function lockSessionKey() {
  state.unlockedWallet = null;
}

function deleteSessionKey() {
  localStorage.removeItem(CONFIG.storageKey);
  state.sessionKey = null;
  state.unlockedWallet = null;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * UI Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

function $(id) {
  return document.getElementById(id);
}

function showToast(message, type = 'info') {
  const container = $('toastContainer');
  const icons = {
    success: '✅',
    error: '❌',
    info: 'ℹ️',
  };
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type]}</span>
    <span class="toast-message">${message}</span>
  `;
  
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function formatAddress(address) {
  return `${address.slice(0, 8)}...${address.slice(-6)}`;
}

function formatExpiry(timestamp) {
  const date = new Date(timestamp * 1000);
  const now = new Date();
  const diff = date - now;
  
  if (diff < 0) return 'Expired';
  
  const hours = Math.floor(diff / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
  
  if (hours > 24) {
    const days = Math.floor(hours / 24);
    return `${days} day${days > 1 ? 's' : ''} remaining`;
  }
  
  return `${hours}h ${minutes}m remaining`;
}

function updateUI() {
  const hasKey = state.sessionKey !== null;
  const isUnlocked = state.unlockedWallet !== null;
  
  // Show/hide cards in session section
  const createKeyCard = $('createKeyCard');
  const keyInfoCard = $('keyInfoCard');
  const importKeyCard = $('importKeyCard');
  
  if (createKeyCard) createKeyCard.style.display = hasKey ? 'none' : 'block';
  if (keyInfoCard) keyInfoCard.style.display = hasKey ? 'block' : 'none';
  if (importKeyCard) importKeyCard.style.display = hasKey ? 'none' : 'block';
  
  // Update key status badge
  const keyStatus = $('keyStatus');
  if (keyStatus) {
    keyStatus.textContent = isUnlocked ? 'Unlocked' : 'Locked';
    keyStatus.className = `status-badge ${isUnlocked ? 'unlocked' : ''}`;
  }
  
  // Update navbar session info
  const sessionStatus = $('sessionStatus');
  const navKeyAddress = $('navKeyAddress');
  const navKeyBalance = $('navKeyBalance');
  const navUnlockBtn = $('navUnlockBtn');
  const donateNavBtn = $('donateNavBtn');
  
  if (sessionStatus) {
    sessionStatus.className = `session-status ${isUnlocked ? 'unlocked' : ''}`;
  }
  
  if (navKeyAddress) {
    navKeyAddress.textContent = hasKey ? formatAddress(state.sessionKey.address) : 'No Session Key';
  }
  
  if (navUnlockBtn) {
    navUnlockBtn.style.display = hasKey && !isUnlocked ? 'inline-flex' : 'none';
  }
  
  if (donateNavBtn) {
    donateNavBtn.style.display = isUnlocked && CONFIG.gasSponsorAddress ? 'inline-flex' : 'none';
  }
  
  // Update key details
  if (hasKey) {
    const keyAddress = $('keyAddress');
    const keyExpiry = $('keyExpiry');
    const faucetAddress = $('faucetAddress');
    
    if (keyAddress) keyAddress.textContent = state.sessionKey.address;
    if (keyExpiry) keyExpiry.textContent = formatExpiry(state.sessionKey.expiry);
    if (faucetAddress) faucetAddress.textContent = formatAddress(state.sessionKey.address);
  }
  
  // Show/hide unlock form vs key actions
  const unlockForm = $('unlockForm');
  const keyActions = $('keyActions');
  
  if (unlockForm) unlockForm.style.display = isUnlocked ? 'none' : 'flex';
  if (keyActions) keyActions.style.display = isUnlocked ? 'flex' : 'none';
  
  // Enable/disable buttons
  const signMessageBtn = $('signMessageBtn');
  const sendTxBtn = $('sendTxBtn');
  const unlockBtn = $('unlockBtn');
  const unlockPassword = $('unlockPassword');
  const generateQrBtn = $('generateQrBtn');
  const donateBtn = $('donateBtn');
  
  if (signMessageBtn) signMessageBtn.disabled = !isUnlocked;
  if (sendTxBtn) sendTxBtn.disabled = !isUnlocked;
  if (unlockBtn) unlockBtn.disabled = isUnlocked;
  if (unlockPassword) unlockPassword.disabled = isUnlocked;
  if (generateQrBtn) generateQrBtn.disabled = !hasKey;
  if (donateBtn) donateBtn.disabled = !isUnlocked;
  
  // Gas sponsor config card - always show but change content based on state
  const deployGasSponsorCard = $('deployGasSponsorCard');
  const clearBtn = $('clearGasSponsorBtn');
  if (deployGasSponsorCard) {
    // Always visible so user can change config
    deployGasSponsorCard.style.display = 'block';
  }
  if (clearBtn) {
    clearBtn.style.display = CONFIG.gasSponsorAddress ? 'inline-flex' : 'none';
  }
  
  // Update balance if unlocked
  if (isUnlocked) {
    refreshBalance();
  }

  // Check gas sponsor status
  updateGasSponsorUI();
}

async function updateGasSponsorUI() {
  const sponsorStatus = $('sponsorStatus');
  const gasSponsorCheckbox = $('gasSponsorCheckbox');
  const gasPoolBalance = $('gasPoolBalance');
  const gasBudget = $('gasBudget');
  const gasStatus = $('gasStatus');
  
  if (!CONFIG.gasSponsorAddress) {
    if (gasSponsorCheckbox) gasSponsorCheckbox.style.display = 'none';
    if (gasPoolBalance) gasPoolBalance.textContent = 'Not configured';
    if (gasBudget) gasBudget.textContent = '-';
    if (gasStatus) gasStatus.textContent = 'Disabled';
    return;
  }

  if (gasSponsorCheckbox) gasSponsorCheckbox.style.display = 'block';
  
  if (!state.sessionKey) {
    if (sponsorStatus) {
      sponsorStatus.textContent = 'Create a session key first';
      sponsorStatus.className = 'sponsor-status';
    }
    if (gasPoolBalance) gasPoolBalance.textContent = '-';
    if (gasBudget) gasBudget.textContent = '-';
    if (gasStatus) gasStatus.textContent = 'No key';
    return;
  }

  try {
    const status = await checkGasSponsorStatus();
    
    if (gasPoolBalance) gasPoolBalance.textContent = `${parseFloat(status.contractBalance || 0).toFixed(4)} ETH`;
    if (gasBudget) gasBudget.textContent = status.isAllowed ? `${status.remainingBudget} ETH` : 'Not registered';
    if (gasStatus) gasStatus.textContent = status.isAllowed ? '✅ Active' : '⚠️ Not registered';
    
    if (sponsorStatus) {
      if (status.isAllowed) {
        sponsorStatus.innerHTML = `✅ Your session key is registered for gas sponsorship!`;
        sponsorStatus.className = 'sponsor-status allowed';
      } else {
        sponsorStatus.innerHTML = `⚠️ Not registered. Contact the pool owner to add your address.`;
        sponsorStatus.className = 'sponsor-status not-allowed';
      }
    }
    
    const useGasSponsor = $('useGasSponsor');
    if (useGasSponsor) {
      useGasSponsor.disabled = !status.isAllowed;
      if (!status.isAllowed) useGasSponsor.checked = false;
    }

  } catch (e) {
    if (sponsorStatus) {
      sponsorStatus.textContent = 'Failed to check gas sponsor status';
      sponsorStatus.className = 'sponsor-status';
    }
    if (gasPoolBalance) gasPoolBalance.textContent = 'Error';
    if (gasBudget) gasBudget.textContent = 'Error';
    if (gasStatus) gasStatus.textContent = 'Error';
  }
}

async function refreshBalance() {
  if (!state.sessionKey || !state.provider) return;
  
  try {
    const balance = await state.provider.getBalance(state.sessionKey.address);
    const formatted = ethers.formatEther(balance);
    const balanceStr = parseFloat(formatted).toFixed(4);
    
    // Update main balance display
    const keyBalance = $('keyBalance');
    if (keyBalance) keyBalance.textContent = balanceStr;
    
    // Update navbar balance
    const navKeyBalance = $('navKeyBalance');
    if (navKeyBalance) navKeyBalance.textContent = `${balanceStr} ETH`;
  } catch (e) {
    console.error('Failed to fetch balance:', e);
  }
}

function displayMnemonic(mnemonic) {
  const words = mnemonic.split(' ');
  const container = $('mnemonicWords');
  container.innerHTML = words.map((word, i) => `
    <div class="mnemonic-word">
      <span class="num">${i + 1}.</span>
      ${word}
    </div>
  `).join('');
  
  $('mnemonicDisplay').style.display = 'block';
}

function hideMnemonic() {
  $('mnemonicDisplay').style.display = 'none';
  $('mnemonicWords').innerHTML = '';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Event Handlers
 * ═══════════════════════════════════════════════════════════════════════════ */

async function handleCreateKey() {
  const password = $('password').value;
  const expiry = parseInt($('expiry').value);
  const withMnemonic = $('withMnemonic').checked;
  
  if (password.length < 8) {
    showToast('Password must be at least 8 characters', 'error');
    return;
  }
  
  try {
    $('createKeyBtn').classList.add('loading');
    $('createKeyBtn').disabled = true;
    
    const { sessionKey, mnemonic } = await createSessionKey(password, expiry, withMnemonic);
    state.sessionKey = sessionKey;
    
    showToast('Session key created successfully!', 'success');
    
    // Show mnemonic if generated
    if (mnemonic) {
      displayMnemonic(mnemonic);
    }
    
    // Clear password field
    $('password').value = '';
    
    updateUI();
    
  } catch (e) {
    showToast(`Failed to create key: ${e.message}`, 'error');
  } finally {
    $('createKeyBtn').classList.remove('loading');
    $('createKeyBtn').disabled = false;
  }
}

async function handleUnlock() {
  const password = $('unlockPassword').value;
  
  if (!password) {
    showToast('Please enter your password', 'error');
    return;
  }
  
  try {
    $('unlockBtn').classList.add('loading');
    $('unlockBtn').disabled = true;
    
    await unlockSessionKey(password);
    
    showToast('Session key unlocked!', 'success');
    $('unlockPassword').value = '';
    
    updateUI();
    
  } catch (e) {
    showToast(`Failed to unlock: ${e.message}`, 'error');
  } finally {
    $('unlockBtn').classList.remove('loading');
    $('unlockBtn').disabled = false;
  }
}

async function handleDeleteKey() {
  if (!confirm('Are you sure you want to delete this session key? This cannot be undone.')) {
    return;
  }
  
  deleteSessionKey();
  showToast('Session key deleted', 'info');
  updateUI();
}

async function handleSignMessage() {
  const message = $('messageToSign').value;
  
  if (!message) {
    showToast('Please enter a message to sign', 'error');
    return;
  }
  
  if (!state.unlockedWallet) {
    showToast('Please unlock your session key first', 'error');
    return;
  }
  
  try {
    $('signMessageBtn').classList.add('loading');
    $('signMessageBtn').disabled = true;
    
    const signature = await state.unlockedWallet.signMessage(message);
    
    $('signatureOutput').textContent = signature;
    $('signatureResult').style.display = 'block';
    
    showToast('Message signed successfully!', 'success');
    
  } catch (e) {
    showToast(`Failed to sign: ${e.message}`, 'error');
  } finally {
    $('signMessageBtn').classList.remove('loading');
    $('signMessageBtn').disabled = false;
  }
}

async function handleSendTransaction() {
  const recipient = $('recipientAddress').value;
  const amount = $('sendAmount').value;
  const txMessage = $('txMessage')?.value || '';
  const useGasSponsor = $('useGasSponsor')?.checked && CONFIG.gasSponsorAddress;
  
  if (!ethers.isAddress(recipient)) {
    showToast('Invalid recipient address', 'error');
    return;
  }
  
  if (!amount || parseFloat(amount) <= 0) {
    showToast('Invalid amount', 'error');
    return;
  }
  
  if (!state.unlockedWallet) {
    showToast('Please unlock your session key first', 'error');
    return;
  }
  
  try {
    $('sendTxBtn').classList.add('loading');
    $('sendTxBtn').disabled = true;
    
    // Show pending status
    $('txResult').style.display = 'block';
    $('txStatus').className = 'tx-status pending';
    $('txLink').style.display = 'none';

    let tx;

    if (useGasSponsor) {
      // Use gas sponsor for meta-transaction
      $('txStatus').innerHTML = '⏳ Signing meta-transaction...';
      tx = await sendSponsoredTransaction(recipient, amount);
    } else {
      // Direct transaction (session key pays gas)
      $('txStatus').innerHTML = '⏳ Sending transaction...';
      
      // Prepare transaction with optional message data
      const txData = {
        to: recipient,
        value: ethers.parseEther(amount),
      };
      
      // If message provided, encode it as hex data (visible on Etherscan!)
      if (txMessage.trim()) {
        txData.data = ethers.hexlify(ethers.toUtf8Bytes(txMessage));
      }
      
      // Send transaction
      tx = await state.unlockedWallet.sendTransaction(txData);
    }
    
    $('txStatus').innerHTML = '⏳ Waiting for confirmation...';
    $('txLink').href = `${CONFIG.explorerUrl}/tx/${tx.hash}`;
    $('txLink').style.display = 'inline';
    
    // Wait for confirmation
    const receipt = await tx.wait();
    
    $('txStatus').className = 'tx-status success';
    $('txStatus').innerHTML = `✅ Transaction confirmed! (Block ${receipt.blockNumber})`;
    
    showToast('Transaction sent successfully!', 'success');
    
    // Refresh balance
    refreshBalance();
    
  } catch (e) {
    $('txStatus').className = 'tx-status error';
    $('txStatus').innerHTML = `❌ ${e.message}`;
    showToast(`Transaction failed: ${e.message}`, 'error');
  } finally {
    $('sendTxBtn').classList.remove('loading');
    $('sendTxBtn').disabled = state.unlockedWallet === null;
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Gas Sponsor Meta-Transactions
 * ═══════════════════════════════════════════════════════════════════════════ */

async function sendSponsoredTransaction(recipient, amount) {
  if (!CONFIG.gasSponsorAddress) {
    throw new Error('Gas sponsor not configured');
  }

  const gasSponsor = new ethers.Contract(
    CONFIG.gasSponsorAddress,
    GAS_SPONSOR_ABI,
    state.provider
  );

  const signerAddress = state.unlockedWallet.address;
  const value = ethers.parseEther(amount);
  const deadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
  
  // Get current nonce from contract
  const nonce = await gasSponsor.nonces(signerAddress);
  
  // Check if signer is allowed
  const isAllowed = await gasSponsor.isSignerAllowed(signerAddress);
  if (!isAllowed) {
    throw new Error('Session key not registered with gas sponsor. Ask the owner to add your address: ' + signerAddress);
  }

  // Get the message hash to sign
  const messageHash = await gasSponsor.getTransferHash(
    signerAddress,
    recipient,
    value,
    deadline,
    nonce
  );

  // Sign the message
  const signature = await state.unlockedWallet.signMessage(ethers.getBytes(messageHash));

  // Create a new signer that will pay gas (could be a relayer)
  // For demo, we'll use a public relayer or the user needs some gas
  // In production, you'd have a backend relayer submit this
  
  // For now, we'll try to submit directly - the contract pays for the actual transfer
  // but someone needs to pay for the meta-tx submission
  const relayerWallet = state.unlockedWallet; // In production, use a funded relayer
  
  const gasSponsorWithSigner = gasSponsor.connect(relayerWallet);
  
  const tx = await gasSponsorWithSigner.executeTransfer(
    signerAddress,
    recipient,
    value,
    deadline,
    nonce,
    signature
  );

  return tx;
}

async function checkGasSponsorStatus() {
  if (!CONFIG.gasSponsorAddress || !state.sessionKey) {
    return { available: false };
  }

  try {
    const gasSponsor = new ethers.Contract(
      CONFIG.gasSponsorAddress,
      GAS_SPONSOR_ABI,
      state.provider
    );

    const isAllowed = await gasSponsor.isSignerAllowed(state.sessionKey.address);
    const remainingBudget = isAllowed 
      ? await gasSponsor.getRemainingBudget(state.sessionKey.address)
      : 0n;
    
    // Get contract balance
    const contractBalance = await state.provider.getBalance(CONFIG.gasSponsorAddress);

    return {
      available: true,
      isAllowed,
      remainingBudget: ethers.formatEther(remainingBudget),
      contractBalance: ethers.formatEther(contractBalance),
      contractAddress: CONFIG.gasSponsorAddress,
    };
  } catch (e) {
    console.error('Gas sponsor check failed:', e);
    return { available: false, error: e.message };
  }
}

function handleSaveGasSponsor() {
  const input = $('gasSponsorInput');
  const address = input?.value?.trim();

  if (!address) {
    showToast('Please enter a contract address', 'error');
    return;
  }

  if (!ethers.isAddress(address)) {
    showToast('Invalid Ethereum address', 'error');
    return;
  }

  // Save to config and localStorage
  CONFIG.gasSponsorAddress = address;
  localStorage.setItem('gasSponsorAddress', address);

  showToast('✅ Gas Sponsor configured!', 'success');
  
  // Update UI
  updateUI();
  updateGasSponsorUI();
  
  // Show clear button
  const clearBtn = $('clearGasSponsorBtn');
  if (clearBtn) clearBtn.style.display = 'inline-flex';
}

function handleClearGasSponsor() {
  CONFIG.gasSponsorAddress = null;
  localStorage.removeItem('gasSponsorAddress');
  
  const input = $('gasSponsorInput');
  if (input) input.value = '';
  
  const clearBtn = $('clearGasSponsorBtn');
  if (clearBtn) clearBtn.style.display = 'none';

  showToast('Gas Sponsor cleared', 'info');
  
  // Update UI
  updateUI();
  updateGasSponsorUI();
}

async function handleDonateToSponsor() {
  const amountInput = $('donateAmount');
  const amount = amountInput.value;

  if (!amount || parseFloat(amount) <= 0) {
    showToast('Please enter an amount to donate', 'error');
    return;
  }

  if (!state.unlockedWallet) {
    showToast('Please unlock your session key first', 'error');
    return;
  }

  if (!CONFIG.gasSponsorAddress) {
    showToast('Gas sponsor not configured', 'error');
    return;
  }

  try {
    $('donateBtn').classList.add('loading');
    $('donateBtn').disabled = true;

    const tx = await state.unlockedWallet.sendTransaction({
      to: CONFIG.gasSponsorAddress,
      value: ethers.parseEther(amount),
    });

    showToast('Donation sent! Waiting for confirmation...', 'info');

    await tx.wait();

    showToast(`Successfully donated ${amount} ETH to gas sponsor pool!`, 'success');
    amountInput.value = '';
    
    // Refresh balance and sponsor status
    refreshBalance();
    updateGasSponsorUI();

  } catch (e) {
    showToast(`Donation failed: ${e.message}`, 'error');
  } finally {
    $('donateBtn').classList.remove('loading');
    $('donateBtn').disabled = false;
  }
}

async function handleDonateAll() {
  if (!state.unlockedWallet || !state.sessionKey) {
    showToast('Please unlock your session key first', 'error');
    return;
  }

  try {
    // Get current balance
    const balance = await state.provider.getBalance(state.sessionKey.address);
    
    // Estimate gas for the transfer
    const gasPrice = await state.provider.getFeeData();
    const gasLimit = 21000n; // Standard ETH transfer
    const gasCost = gasLimit * (gasPrice.gasPrice || 0n);
    
    // Calculate max amount (balance - gas cost - small buffer)
    const buffer = ethers.parseEther('0.0001'); // Small buffer for safety
    const maxAmount = balance - gasCost - buffer;

    if (maxAmount <= 0n) {
      showToast('Insufficient balance to donate (need to cover gas)', 'error');
      return;
    }

    $('donateAmount').value = ethers.formatEther(maxAmount);
    showToast(`Max donation amount set: ${ethers.formatEther(maxAmount)} ETH`, 'info');

  } catch (e) {
    showToast(`Failed to calculate max amount: ${e.message}`, 'error');
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * QR Code Sync Feature
 * ═══════════════════════════════════════════════════════════════════════════ */

let scannerStream = null;
let scannerInterval = null;

// QR code functions are now inline in the sync section

function generateQrCode() {
  if (!state.sessionKey) {
    showToast('No session key to export', 'error');
    return;
  }
  
  // Create compact export data (encrypted - still needs password to use)
  // Use short keys to minimize QR code size
  const exportData = {
    v: 1,  // version
    t: 'ssk',  // type: symmio-session-key
    a: state.sessionKey.address,
    e: state.sessionKey.encryptedPrivateKey,
    s: state.sessionKey.salt,
    i: state.sessionKey.iv,
    x: state.sessionKey.expiry,
  };
  
  const jsonString = JSON.stringify(exportData);
  console.log('QR data length:', jsonString.length, 'chars');
  
  // Get the container div and clear it
  const qrContainer = $('qrCodeContainer');
  if (!qrContainer) {
    showToast('QR container not found', 'error');
    return;
  }
  qrContainer.innerHTML = '';
  
  try {
    // Check which QR library is available
    if (typeof window.qrcode !== 'undefined') {
      // qrcode-generator library
      const qr = window.qrcode(0, 'L');
      qr.addData(jsonString);
      qr.make();
      qrContainer.innerHTML = qr.createImgTag(4, 8);
      console.log('QR code generated with qrcode-generator');
    } else if (typeof window.QRCode !== 'undefined') {
      // qrcodejs library fallback
      new window.QRCode(qrContainer, {
        text: jsonString,
        width: 256,
        height: 256,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: window.QRCode.CorrectLevel?.L || 1
      });
      console.log('QR code generated with qrcodejs');
    } else {
      console.error('No QR code library loaded');
      showToast('QR code library not loaded. Please refresh the page.', 'error');
      return;
    }
    
    showToast('QR code generated!', 'success');
  } catch (error) {
    console.error('QR Code generation error:', error);
    showToast('Failed to generate QR code: ' + error.message, 'error');
  }
}

async function startScanner() {
  console.log('Starting scanner...');
  
  // Check if we're on HTTPS (required for camera on mobile)
  const isSecure = window.location.protocol === 'https:' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
  
  if (!isSecure && isMobile) {
    showToast('Camera requires HTTPS on mobile devices. Please use the HTTPS URL or access from desktop.', 'error');
    console.error('Camera access blocked: HTTPS required on mobile');
    return;
  }
  
  // Check if mediaDevices is available
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showToast('Camera not supported on this browser. Try Chrome or Safari.', 'error');
    console.error('mediaDevices API not available');
    return;
  }
  
  // Check if jsQR library is loaded
  const jsQRLib = window.jsQR || window.JSQR;
  if (typeof jsQRLib === 'undefined') {
    console.error('jsQR library not loaded. Available globals:', Object.keys(window).filter(k => k.toLowerCase().includes('qr')));
    showToast('Scanner library not loaded. Please refresh the page.', 'error');
    return;
  }
  console.log('jsQR library loaded successfully');
  
  try {
    const video = $('scannerVideo');
    const canvas = $('scannerCanvas');
    
    if (!video || !canvas) {
      console.error('Video or canvas element not found');
      showToast('Scanner elements not found', 'error');
      return;
    }
    
    const ctx = canvas.getContext('2d');
    
    // Request camera access
    console.log('Requesting camera access...');
    scannerStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' }
    });
    
    video.srcObject = scannerStream;
    await video.play();
    console.log('Camera started, video dimensions:', video.videoWidth, 'x', video.videoHeight);
    
    // Update UI
    $('startScanBtn').style.display = 'none';
    $('stopScanBtn').style.display = 'inline-flex';
    $('scanResult').style.display = 'none';
    
    // Wait for video dimensions to be available
    await new Promise(resolve => {
      if (video.videoWidth > 0) {
        resolve();
      } else {
        video.addEventListener('loadedmetadata', resolve, { once: true });
      }
    });
    
    // Set canvas size
    canvas.width = video.videoWidth || 640;
    canvas.height = video.videoHeight || 480;
    console.log('Canvas size set to:', canvas.width, 'x', canvas.height);
    
    // Start scanning
    scannerInterval = setInterval(() => {
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        
        // Use jsQR to detect QR code
        const jsQRFunc = window.jsQR || window.JSQR;
        const code = jsQRFunc(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'dontInvert'
        });
        
        if (code) {
          console.log('QR code detected:', code.data.substring(0, 50) + '...');
          handleScannedCode(code.data);
        }
      }
    }, 100);
    
    showToast('Camera started! Point at a QR code.', 'info');
    
  } catch (error) {
    console.error('Scanner error:', error);
    showToast('Failed to access camera: ' + error.message, 'error');
  }
}

function stopScanner() {
  if (scannerInterval) {
    clearInterval(scannerInterval);
    scannerInterval = null;
  }
  
  if (scannerStream) {
    scannerStream.getTracks().forEach(track => track.stop());
    scannerStream = null;
  }
  
  const video = $('scannerVideo');
  if (video) {
    video.srcObject = null;
  }
  
  $('startScanBtn').style.display = 'inline-flex';
  $('stopScanBtn').style.display = 'none';
}

async function handleScannedCode(data) {
  stopScanner();
  
  try {
    const parsed = JSON.parse(data);
    
    let keyData;
    
    // Support both old format and new compact format
    if (parsed.t === 'ssk' || parsed.type === 'symmio-session-key') {
      // New compact format: { v, t, a, e, s, i, x }
      if (parsed.t === 'ssk') {
        keyData = {
          address: parsed.a,
          encryptedPrivateKey: parsed.e,
          salt: parsed.s,
          iv: parsed.i,
          expiry: parsed.x,
        };
      } 
      // Old format: { version, type, data: {...} }
      else if (parsed.data) {
        keyData = parsed.data;
      } else {
        throw new Error('Invalid QR code format');
      }
    } else {
      throw new Error('Invalid QR code format');
    }
    
    // Validate required fields
    if (!keyData.address || !keyData.encryptedPrivateKey || !keyData.salt || !keyData.iv) {
      throw new Error('Missing required key data');
    }
    
    // Check if key is expired
    if (keyData.expiry * 1000 < Date.now()) {
      throw new Error('This session key has expired');
    }
    
    // Check if we already have a key
    if (state.sessionKey) {
      if (!confirm('This will replace your current session key. Continue?')) {
        return;
      }
    }
    
    // Save the imported key
    const importedKey = {
      id: keyData.id || generateKeyId(),
      address: keyData.address,
      encryptedPrivateKey: keyData.encryptedPrivateKey,
      salt: keyData.salt,
      iv: keyData.iv,
      expiry: keyData.expiry,
      createdAt: keyData.createdAt || Math.floor(Date.now() / 1000),
    };
    
    localStorage.setItem(CONFIG.storageKey, JSON.stringify(importedKey));
    state.sessionKey = importedKey;
    state.unlockedWallet = null;
    
    // Show success
    $('scanResult').style.display = 'block';
    $('scanResult').className = 'scan-result success';
    $('scanResult').innerHTML = `
      ✅ Session key imported!<br>
      <small>Address: ${formatAddress(keyData.address)}</small>
    `;
    
    showToast('Session key imported successfully!', 'success');
    
    // Update UI after delay
    setTimeout(() => {
      stopScanner();
      updateUI();
      // Navigate to session section
      navigateToSection('session');
    }, 2000);
    
  } catch (error) {
    $('scanResult').style.display = 'block';
    $('scanResult').className = 'scan-result error';
    $('scanResult').textContent = '❌ ' + error.message;
    showToast(error.message, 'error');
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Initialization
 * ═══════════════════════════════════════════════════════════════════════════ */

async function init() {
  // Setup provider
  state.provider = new ethers.JsonRpcProvider(CONFIG.rpcUrl, {
    chainId: CONFIG.chainId,
    name: CONFIG.chainName,
  });
  
  // Update network status
  try {
    const network = await state.provider.getNetwork();
    const networkName = $('networkName');
    if (networkName) networkName.textContent = CONFIG.chainName;
  } catch (e) {
    const networkName = $('networkName');
    if (networkName) networkName.textContent = 'Offline';
  }
  
  // Load existing session key
  state.sessionKey = loadSessionKey();
  
  // Load saved gas sponsor address
  const savedGasSponsor = localStorage.getItem('gasSponsorAddress');
  if (savedGasSponsor && ethers.isAddress(savedGasSponsor)) {
    CONFIG.gasSponsorAddress = savedGasSponsor;
    console.log('Loaded Gas Sponsor:', savedGasSponsor);
  }
  
  // Sidebar navigation
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      // Update active nav item
      document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      
      // Show corresponding section
      const sectionId = 'section' + item.dataset.section.charAt(0).toUpperCase() + item.dataset.section.slice(1);
      document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
      const section = $(sectionId);
      if (section) section.classList.add('active');
    });
  });
  
  // Core session key buttons
  $('createKeyBtn')?.addEventListener('click', handleCreateKey);
  $('unlockBtn')?.addEventListener('click', handleUnlock);
  $('deleteKeyBtn')?.addEventListener('click', handleDeleteKey);
  $('signMessageBtn')?.addEventListener('click', handleSignMessage);
  $('sendTxBtn')?.addEventListener('click', handleSendTransaction);
  
  // Navbar buttons
  $('claimEthBtn')?.addEventListener('click', showFaucetModal);
  $('donateNavBtn')?.addEventListener('click', () => navigateToSection('gas'));
  $('navUnlockBtn')?.addEventListener('click', showUnlockModal);
  
  // QR/Sync buttons
  $('showQrBtn')?.addEventListener('click', () => navigateToSection('sync'));
  $('generateQrBtn')?.addEventListener('click', generateQrCode);
  $('startScanBtn')?.addEventListener('click', startScanner);
  $('stopScanBtn')?.addEventListener('click', stopScanner);
  $('openScannerBtn')?.addEventListener('click', () => {
    navigateToSection('sync');
    setTimeout(startScanner, 300);
  });
  
  // Gas sponsor buttons
  $('saveGasSponsorBtn')?.addEventListener('click', handleSaveGasSponsor);
  $('clearGasSponsorBtn')?.addEventListener('click', handleClearGasSponsor);
  $('donateBtn')?.addEventListener('click', handleDonateToSponsor);
  $('donateAllBtn')?.addEventListener('click', handleDonateAll);
  
  // Populate gas sponsor input if saved
  if (CONFIG.gasSponsorAddress) {
    const input = $('gasSponsorInput');
    if (input) input.value = CONFIG.gasSponsorAddress;
    const clearBtn = $('clearGasSponsorBtn');
    if (clearBtn) clearBtn.style.display = 'inline-flex';
  }
  
  // Modal handlers
  $('modalCancelBtn')?.addEventListener('click', hideUnlockModal);
  $('modalUnlockBtn')?.addEventListener('click', handleModalUnlock);
  
  // Enter key handlers
  $('password')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleCreateKey();
  });
  
  $('unlockPassword')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleUnlock();
  });
  
  $('modalUnlockPassword')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleModalUnlock();
  });
  
  // Close modals on backdrop click
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.style.display = 'none';
    });
  });
  
  // Initial UI update
  updateUI();
  
  console.log('🔐 Session Keys Demo initialized');
  console.log(`📡 Connected to ${CONFIG.chainName}`);
}

// Navigation helper
function navigateToSection(sectionName) {
  document.querySelectorAll('.nav-item').forEach(i => {
    i.classList.toggle('active', i.dataset.section === sectionName);
  });
  document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
  const section = $('section' + sectionName.charAt(0).toUpperCase() + sectionName.slice(1));
  if (section) section.classList.add('active');
}

// Faucet modal
function showFaucetModal() {
  const faucetAddress = $('faucetAddress');
  if (faucetAddress && state.sessionKey) {
    faucetAddress.textContent = formatAddress(state.sessionKey.address);
  }
  const modal = $('faucetModal');
  if (modal) modal.style.display = 'flex';
}

function closeFaucetModal() {
  const modal = $('faucetModal');
  if (modal) modal.style.display = 'none';
}

// Unlock modal
function showUnlockModal() {
  const modal = $('unlockModal');
  if (modal) modal.style.display = 'flex';
  $('modalUnlockPassword')?.focus();
}

function hideUnlockModal() {
  const modal = $('unlockModal');
  if (modal) modal.style.display = 'none';
  const input = $('modalUnlockPassword');
  if (input) input.value = '';
}

async function handleModalUnlock() {
  const password = $('modalUnlockPassword')?.value;
  if (!password) {
    showToast('Please enter your password', 'error');
    return;
  }
  
  try {
    const decrypted = await decryptPrivateKey(
      state.sessionKey.encryptedPrivateKey,
      password,
      state.sessionKey.salt,
      state.sessionKey.iv
    );
    
    state.unlockedWallet = new ethers.Wallet(decrypted, state.provider);
    hideUnlockModal();
    updateUI();
    showToast('Session key unlocked!', 'success');
  } catch (e) {
    showToast('Invalid password', 'error');
  }
}

// Global function for copy button
window.copyToClipboard = async function(elementId) {
  const el = $(elementId);
  if (!el) return;
  const text = el.textContent;
  await navigator.clipboard.writeText(text);
  showToast('Copied to clipboard!', 'success');
};

// Global function for refresh button
window.refreshBalance = refreshBalance;

// Global function for mnemonic
window.hideMnemonic = hideMnemonic;

// Global function for faucet modal
window.closeFaucetModal = closeFaucetModal;

// Start the app
init();
