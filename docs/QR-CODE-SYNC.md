# QR Code Scanning to Mobile — Technical Documentation

This document describes how the session key QR code sync feature works, enabling users to transfer encrypted session keys between devices (e.g., desktop → mobile) without exposing the private key.

---

## Table of Contents

1. [Overview](#overview)
2. [User Flow](#user-flow)
3. [Export Flow (Desktop → QR Code)](#export-flow-desktop--qr-code)
4. [Import Flow (Mobile Scans QR Code)](#import-flow-mobile-scans-qr-code)
5. [Data Format](#data-format)
6. [Security Model](#security-model)
7. [Technical Implementation](#technical-implementation)
8. [Browser Requirements](#browser-requirements)
9. [Libraries Used](#libraries-used)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The QR code sync feature allows users to:

1. **Export** a session key from one device (e.g., desktop) by displaying a QR code containing the encrypted key material
2. **Import** that session key on another device (e.g., mobile) by scanning the QR code with the device camera

The key is **never transmitted in plaintext**. The QR code contains only the **encrypted** private key, salt, and IV. The user must enter the same password on the importing device to decrypt and use the key.

---

## User Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EXPORT (Source Device - e.g. Desktop)                 │
└─────────────────────────────────────────────────────────────────────────────┘

  1. User has an unlocked session key
  2. User clicks "Sync to Mobile" or navigates to Sync Device section
  3. User clicks "Generate QR Code"
  4. QR code appears containing encrypted session key data
  5. User holds up the screen for the target device to scan


┌─────────────────────────────────────────────────────────────────────────────┐
│                         IMPORT (Target Device - e.g. Mobile)                  │
└─────────────────────────────────────────────────────────────────────────────┘

  1. User opens the app on the target device
  2. User clicks "Scan QR Code" or "Start Camera"
  3. Browser requests camera permission
  4. User points camera at QR code on source device
  5. QR code is detected and decoded automatically
  6. Session key is imported (stored encrypted in localStorage/IndexedDB)
  7. User enters the SAME password used on the source device
  8. User unlocks the key and can now sign transactions on the new device
```

---

## Export Flow (Desktop → QR Code)

### Step 1: Prepare Export Data

When the user clicks "Generate QR Code", the app builds a compact JSON object from the current session key:

```javascript
const exportData = {
  v: 1,                              // version
  t: 'ssk',                          // type: symmio-session-key
  a: state.sessionKey.address,       // Ethereum address
  e: state.sessionKey.encryptedPrivateKey,  // encrypted private key (base64)
  s: state.sessionKey.salt,           // PBKDF2 salt (base64)
  i: state.sessionKey.iv,             // AES-GCM IV (base64)
  x: state.sessionKey.expiry,         // Unix timestamp when key expires
};
```

Short property names (`v`, `t`, `a`, `e`, `s`, `i`, `x`) are used to minimize QR code size, since QR codes have limited capacity and smaller payloads scan more reliably.

### Step 2: Encode as JSON

The export data is serialized:

```javascript
const jsonString = JSON.stringify(exportData);
```

### Step 3: Render QR Code

The JSON string is passed to a QR code library. The demo supports two libraries:

- **qrcode-generator** (primary): `qrcode(0, 'L')` — error correction level L (low) for smaller codes
- **qrcodejs** (fallback): Same payload, 256×256 pixel output

The QR code is displayed in a container (`#qrCodeContainer`) for the user to present to the scanning device.

---

## Import Flow (Mobile Scans QR Code)

### Step 1: Request Camera Access

The scanner requests access to the device camera:

```javascript
scannerStream = await navigator.mediaDevices.getUserMedia({
  video: { facingMode: 'environment' }  // Rear camera on mobile
});
```

**Important:** On mobile, camera access requires:
- **HTTPS** (or `localhost` / `127.0.0.1` for development)
- User permission when prompted

### Step 2: Capture Video Frames

A `<video>` element displays the camera feed. A hidden `<canvas>` is used to capture frames at ~100ms intervals.

### Step 3: Decode QR Code

Each frame is passed to **jsQR**:

```javascript
const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
const code = jsQR(imageData.data, imageData.width, imageData.height, {
  inversionAttempts: 'dontInvert'
});
```

When a valid QR code is detected, `code.data` contains the raw string (the JSON payload).

### Step 4: Parse and Validate

The scanned string is parsed and validated:

```javascript
const parsed = JSON.parse(data);

// Support new compact format (t === 'ssk') and legacy format
if (parsed.t === 'ssk') {
  keyData = {
    address: parsed.a,
    encryptedPrivateKey: parsed.e,
    salt: parsed.s,
    iv: parsed.i,
    expiry: parsed.x,
  };
}
```

Validation checks:
- Format type (`t === 'ssk'` or `type === 'symmio-session-key'`)
- Required fields present (address, encryptedPrivateKey, salt, iv)
- Key not expired (`expiry * 1000 > Date.now()`)

### Step 5: Store and Unlock

The imported key is saved to `localStorage` (or IndexedDB in the full library):

```javascript
localStorage.setItem(CONFIG.storageKey, JSON.stringify(importedKey));
```

The user then unlocks the key by entering the same password used on the source device. The app uses PBKDF2 + AES-GCM to decrypt the private key in memory.

---

## Data Format

### Compact Export Format (Current)

| Field | Short Key | Description | Example |
|-------|-----------|-------------|---------|
| Version | `v` | Schema version | `1` |
| Type | `t` | Payload type | `'ssk'` |
| Address | `a` | Ethereum address | `'0x1234...'` |
| Encrypted Key | `e` | AES-GCM encrypted private key (base64) | `'abc123...'` |
| Salt | `s` | PBKDF2 salt (base64) | `'xyz789...'` |
| IV | `i` | AES-GCM initialization vector (base64) | `'def456...'` |
| Expiry | `x` | Unix timestamp (seconds) | `1739356800` |

### Legacy Format (Backward Compatible)

```json
{
  "version": 1,
  "type": "symmio-session-key",
  "data": {
    "address": "0x...",
    "encryptedPrivateKey": "...",
    "salt": "...",
    "iv": "...",
    "expiry": 1739356800
  }
}
```

---

## Security Model

### What the QR Code Contains

- ✅ Encrypted private key (AES-GCM)
- ✅ Salt and IV (needed for decryption)
- ✅ Public address and expiry
- ❌ **No password** — the password is never encoded in the QR code

### Security Properties

1. **Encryption at rest**: The private key is encrypted with AES-256-GCM. The key is derived from the user's password using PBKDF2 (100,000 iterations) and a random salt.

2. **Password never transmitted**: The user must remember and re-enter the password on the importing device. This prevents shoulder-surfing or screen capture from compromising the key.

3. **Expiry enforced**: Expired keys are rejected during import.

4. **Secure context**: The demo checks for HTTPS on mobile before enabling the camera.

### Threat Model

- **QR code interception**: An attacker who captures the QR code image only obtains encrypted data. Without the password, they cannot decrypt the private key.
- **Camera access**: The app only accesses the camera when the user explicitly starts the scanner. Video is processed locally and not transmitted.

---

## Technical Implementation

### Encryption (Key Creation)

When a session key is created:

1. A random 32-byte private key is generated
2. Password is derived to a key: `PBKDF2(password, salt, 100000, SHA-256) → AES-256 key`
3. Private key is encrypted: `AES-GCM(plaintext, derivedKey, iv)`
4. `encrypted`, `salt`, and `iv` are stored (and later exported to QR)

### Decryption (Key Unlock)

When the user unlocks on the importing device:

1. Salt and IV from theQR payload are used
2. Same PBKDF2 derivation: `deriveKey(password, salt)`
3. AES-GCM decrypt: `decrypt(encrypted, derivedKey, iv)`
4. decrypted private key is used to create an `ethers.Wallet` instance

### File Locations

| Component | File |
|-----------|------|
| QR generation | `demo/app.js` → `generateQrCode()` |
| QR scanning | `demo/app.js` → `startScanner()`, `handleScannedCode()` |
| Scanner UI | `demo/index.html` → Sync Device section |
| Crypto (encrypt/decrypt) | `demo/app.js` (inline) / `src/crypto.ts` |
| Storage | `localStorage` (demo) / `src/storage.ts` (library) |

---

## Browser Requirements

| Requirement | Notes |
|-------------|-------|
| **Web Crypto API** | `crypto.subtle` for PBKDF2 and AES-GCM |
| **MediaDevices API** | `navigator.mediaDevices.getUserMedia` for camera |
| **HTTPS** | Required for camera on mobile (except localhost) |
| **Canvas 2D** | For capturing video frames for QR decoding |

### Recommended Browsers

- Chrome / Edge (Android, Desktop)
- Safari (iOS, macOS)
- Firefox (Desktop, Android)

---

## Libraries Used

| Library | Purpose | CDN |
|---------|---------|-----|
| **qrcode-generator** (v1.4.4) | Generate QR codes from text | `unpkg.com/qrcode-generator@1.4.4/qrcode.js` |
| **jsQR** (v1.4.0) | Decode QR codes from image data | `unpkg.com/jsqr@1.4.0/dist/jsQR.js` |

The demo loads both and uses qrcode-generator as primary, with qrcodejs as fallback if needed.

---

## Troubleshooting

### "Camera requires HTTPS on mobile"

**Cause**: `getUserMedia` requires a secure context on mobile browsers.  
**Solution**: Serve the app over HTTPS, or use `localhost` / `127.0.0.1` for local development.

### "Camera not supported"

**Cause**: Browser lacks `mediaDevices.getUserMedia`, or user denied permission.  
**Solution**: Use Chrome or Safari; ensure the user grants camera access when prompted.

### "Scanner library not loaded"

**Cause**: jsQR script failed to load (e.g., network issue, ad blocker).  
**Solution**: Check browser console; ensure scripts from unpkg.com load. Consider self-hosting the libraries.

### "Invalid QR code format"

**Cause**: Scanned QR code is not a valid session key payload (wrong app, corrupted scan).  
**Solution**: Regenerate the QR code on the source device; ensure good lighting and focus.

### "This session key has expired"

**Cause**: `expiry` timestamp is in the past.  
**Solution**: Create a new session key on the source device and export again.

### "Invalid password" when unlocking imported key

**Cause**: Different password entered, or key data was corrupted.  
**Solution**: Use the exact same password as on the source device. If importing from a fresh QR scan, password mismatch is the usual cause.

---

## Summary

The QR code sync feature provides a secure, offline way to transfer session keys between devices. The private key remains encrypted throughout the transfer; only the user's password (entered separately on each device) can decrypt it. The implementation uses compact JSON encoding, standard QR libraries, and the Web Crypto API for encryption.
