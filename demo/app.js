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
  
  // Storage key
  storageKey: 'symmio-session-key',
};

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
  
  // Show/hide sections
  $('createKeySection').style.display = hasKey ? 'none' : 'block';
  $('keyInfoSection').style.display = hasKey ? 'block' : 'none';
  $('importKeySection').style.display = hasKey ? 'none' : 'block';
  
  // Update key status
  $('keyStatus').textContent = isUnlocked ? 'Unlocked' : 'Locked';
  $('keyStatus').className = `key-status ${isUnlocked ? 'unlocked' : ''}`;
  
  // Update key details
  if (hasKey) {
    $('keyAddress').textContent = state.sessionKey.address;
    $('keyExpiry').textContent = formatExpiry(state.sessionKey.expiry);
  }
  
  // Enable/disable buttons
  $('signMessageBtn').disabled = !isUnlocked;
  $('sendTxBtn').disabled = !isUnlocked;
  $('unlockBtn').disabled = isUnlocked;
  $('unlockPassword').disabled = isUnlocked;
  
  // Update balance if unlocked
  if (isUnlocked) {
    refreshBalance();
  }
}

async function refreshBalance() {
  if (!state.sessionKey || !state.provider) return;
  
  try {
    const balance = await state.provider.getBalance(state.sessionKey.address);
    const formatted = ethers.formatEther(balance);
    $('keyBalance').textContent = parseFloat(formatted).toFixed(4);
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
    $('txStatus').innerHTML = '⏳ Sending transaction...';
    $('txLink').style.display = 'none';
    
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
    const tx = await state.unlockedWallet.sendTransaction(txData);
    
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
 * QR Code Sync Feature
 * ═══════════════════════════════════════════════════════════════════════════ */

let scannerStream = null;
let scannerInterval = null;

function showQrModal(tab = 'show') {
  $('qrModal').style.display = 'flex';
  switchQrTab(tab);
  
  if (tab === 'show' && state.sessionKey) {
    generateQrCode();
  }
}

function hideQrModal() {
  $('qrModal').style.display = 'none';
  stopScanner();
}

function switchQrTab(tabName) {
  // Update tab buttons
  document.querySelectorAll('.qr-tab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.tab === tabName);
  });
  
  // Update tab content
  $('showQrTab').classList.toggle('active', tabName === 'show');
  $('scanQrTab').classList.toggle('active', tabName === 'scan');
  
  // Stop scanner if switching away
  if (tabName !== 'scan') {
    stopScanner();
  }
}

function generateQrCode() {
  if (!state.sessionKey) return;
  
  // Create export data (encrypted - still needs password to use)
  const exportData = {
    version: 1,
    type: 'symmio-session-key',
    data: {
      id: state.sessionKey.id,
      address: state.sessionKey.address,
      encryptedPrivateKey: state.sessionKey.encryptedPrivateKey,
      salt: state.sessionKey.salt,
      iv: state.sessionKey.iv,
      expiry: state.sessionKey.expiry,
      createdAt: state.sessionKey.createdAt,
    }
  };
  
  const jsonString = JSON.stringify(exportData);
  const canvas = $('qrCanvas');
  
  // Generate QR code
  QRCode.toCanvas(canvas, jsonString, {
    width: 280,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#ffffff'
    },
    errorCorrectionLevel: 'M'
  }, function(error) {
    if (error) {
      console.error('QR Code generation error:', error);
      showToast('Failed to generate QR code', 'error');
    }
  });
}

async function startScanner() {
  try {
    const video = $('scannerVideo');
    const canvas = $('scannerCanvas');
    const ctx = canvas.getContext('2d');
    
    // Request camera access
    scannerStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' }
    });
    
    video.srcObject = scannerStream;
    await video.play();
    
    // Update UI
    $('startScanBtn').style.display = 'none';
    $('stopScanBtn').style.display = 'inline-flex';
    $('scanResult').style.display = 'none';
    
    // Set canvas size
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    
    // Start scanning
    scannerInterval = setInterval(() => {
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        
        // Use jsQR to detect QR code
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'dontInvert'
        });
        
        if (code) {
          handleScannedCode(code.data);
        }
      }
    }, 100);
    
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
    
    // Validate the data structure
    if (parsed.type !== 'symmio-session-key' || !parsed.data) {
      throw new Error('Invalid QR code format');
    }
    
    const keyData = parsed.data;
    
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
    
    // Close modal after delay
    setTimeout(() => {
      hideQrModal();
      updateUI();
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
    $('networkName').textContent = `${CONFIG.chainName} (${network.chainId})`;
    $('networkBadge').classList.add('connected');
  } catch (e) {
    $('networkName').textContent = 'Connection Failed';
  }
  
  // Load existing session key
  state.sessionKey = loadSessionKey();
  
  // Setup event listeners
  $('createKeyBtn').addEventListener('click', handleCreateKey);
  $('unlockBtn').addEventListener('click', handleUnlock);
  $('deleteKeyBtn').addEventListener('click', handleDeleteKey);
  $('signMessageBtn').addEventListener('click', handleSignMessage);
  $('sendTxBtn').addEventListener('click', handleSendTransaction);
  
  // QR Code event listeners
  $('showQrBtn').addEventListener('click', () => showQrModal('show'));
  $('closeQrModal').addEventListener('click', hideQrModal);
  $('startScanBtn').addEventListener('click', startScanner);
  $('stopScanBtn').addEventListener('click', stopScanner);
  $('openScannerBtn')?.addEventListener('click', () => showQrModal('scan'));
  
  // QR Tab switching
  document.querySelectorAll('.qr-tab').forEach(tab => {
    tab.addEventListener('click', () => switchQrTab(tab.dataset.tab));
  });
  
  // Close modal on backdrop click
  $('qrModal').addEventListener('click', (e) => {
    if (e.target === $('qrModal')) hideQrModal();
  });
  
  // Enter key handlers
  $('password').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleCreateKey();
  });
  
  $('unlockPassword').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleUnlock();
  });
  
  // Initial UI update
  updateUI();
  
  console.log('🔐 Session Keys Demo initialized');
  console.log(`📡 Connected to ${CONFIG.chainName}`);
  console.log(`📬 Send ETH to: ${CONFIG.recipientAddress}`);
}

// Global function for copy button
window.copyToClipboard = async function(elementId) {
  const text = $(elementId).textContent;
  await navigator.clipboard.writeText(text);
  showToast('Copied to clipboard!', 'success');
};

// Global function for refresh button
window.refreshBalance = refreshBalance;

// Global function for mnemonic
window.hideMnemonic = hideMnemonic;

// Start the app
init();
