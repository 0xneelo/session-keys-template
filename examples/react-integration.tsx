/**
 * React Integration Example
 * Demonstrates using session-keys in a React application
 */

import React, { useState, useEffect, useCallback, createContext, useContext } from 'react';
import {
  SessionKeyManager,
  StoredSessionKey,
  UnlockedSessionKey,
  SCOPE_BUNDLES,
  SessionKeyEvent,
} from '../src';

// ========================================
// Context & Provider
// ========================================

interface SessionKeyContextValue {
  manager: SessionKeyManager;
  keys: StoredSessionKey[];
  unlockedKey: UnlockedSessionKey | null;
  isLoading: boolean;
  error: string | null;
  createKey: (password: string, subAccount: string) => Promise<void>;
  unlockKey: (keyId: string, password: string) => Promise<void>;
  lockKey: () => void;
  deleteKey: (keyId: string) => Promise<void>;
  signMessage: (message: string) => Promise<string | null>;
}

const SessionKeyContext = createContext<SessionKeyContextValue | null>(null);

export function SessionKeyProvider({ children }: { children: React.ReactNode }) {
  const [manager] = useState(() => new SessionKeyManager());
  const [keys, setKeys] = useState<StoredSessionKey[]>([]);
  const [unlockedKey, setUnlockedKey] = useState<UnlockedSessionKey | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load keys on mount
  useEffect(() => {
    async function loadKeys() {
      try {
        const validKeys = await manager.listValid();
        setKeys(validKeys);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load keys');
      } finally {
        setIsLoading(false);
      }
    }
    loadKeys();
  }, [manager]);

  // Subscribe to events
  useEffect(() => {
    const unsubscribe = manager.on((event: SessionKeyEvent) => {
      switch (event.type) {
        case 'created':
          setKeys(prev => [...prev, event.key]);
          break;
        case 'deleted':
          setKeys(prev => prev.filter(k => k.id !== event.keyId));
          if (unlockedKey?.id === event.keyId) {
            setUnlockedKey(null);
          }
          break;
        case 'expired':
          setKeys(prev => prev.filter(k => k.id !== event.keyId));
          if (unlockedKey?.id === event.keyId) {
            setUnlockedKey(null);
          }
          break;
        case 'unlocked':
          setUnlockedKey(event.key);
          break;
        case 'locked':
          if (unlockedKey?.id === event.keyId) {
            setUnlockedKey(null);
          }
          break;
      }
    });

    return unsubscribe;
  }, [manager, unlockedKey]);

  const createKey = useCallback(async (password: string, subAccount: string) => {
    setError(null);
    try {
      await manager.create({
        password,
        expiryDuration: 86400, // 24 hours
        scopes: SCOPE_BUNDLES.TRADING_BASIC,
        subAccountAddress: subAccount,
        chainId: 42161,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create key');
      throw err;
    }
  }, [manager]);

  const unlockKey = useCallback(async (keyId: string, password: string) => {
    setError(null);
    try {
      await manager.unlock(keyId, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unlock key');
      throw err;
    }
  }, [manager]);

  const lockKey = useCallback(() => {
    if (unlockedKey) {
      manager.lock(unlockedKey.id);
    }
  }, [manager, unlockedKey]);

  const deleteKey = useCallback(async (keyId: string) => {
    setError(null);
    try {
      await manager.delete(keyId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete key');
      throw err;
    }
  }, [manager]);

  const signMessage = useCallback(async (message: string): Promise<string | null> => {
    if (!unlockedKey) return null;
    try {
      return await manager.signMessage(unlockedKey.id, message);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to sign');
      return null;
    }
  }, [manager, unlockedKey]);

  return (
    <SessionKeyContext.Provider value={{
      manager,
      keys,
      unlockedKey,
      isLoading,
      error,
      createKey,
      unlockKey,
      lockKey,
      deleteKey,
      signMessage,
    }}>
      {children}
    </SessionKeyContext.Provider>
  );
}

export function useSessionKey() {
  const context = useContext(SessionKeyContext);
  if (!context) {
    throw new Error('useSessionKey must be used within SessionKeyProvider');
  }
  return context;
}

// ========================================
// Components
// ========================================

function CreateKeyForm() {
  const { createKey, error } = useSessionKey();
  const [password, setPassword] = useState('');
  const [subAccount, setSubAccount] = useState('');
  const [creating, setCreating] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    try {
      await createKey(password, subAccount);
      setPassword('');
      setSubAccount('');
    } finally {
      setCreating(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="create-key-form">
      <h3>Create Session Key</h3>
      
      <input
        type="text"
        placeholder="Sub-account address (0x...)"
        value={subAccount}
        onChange={(e) => setSubAccount(e.target.value)}
        required
      />
      
      <input
        type="password"
        placeholder="Password (min 8 chars)"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        minLength={8}
        required
      />
      
      <button type="submit" disabled={creating}>
        {creating ? 'Creating...' : 'Create Key'}
      </button>
      
      {error && <p className="error">{error}</p>}
    </form>
  );
}

function KeyList() {
  const { keys, unlockedKey, deleteKey } = useSessionKey();

  if (keys.length === 0) {
    return <p>No session keys. Create one to get started.</p>;
  }

  return (
    <div className="key-list">
      <h3>Your Session Keys</h3>
      {keys.map(key => (
        <KeyCard
          key={key.id}
          sessionKey={key}
          isUnlocked={unlockedKey?.id === key.id}
          onDelete={() => deleteKey(key.id)}
        />
      ))}
    </div>
  );
}

function KeyCard({ 
  sessionKey, 
  isUnlocked, 
  onDelete 
}: { 
  sessionKey: StoredSessionKey;
  isUnlocked: boolean;
  onDelete: () => void;
}) {
  const { unlockKey, lockKey } = useSessionKey();
  const [password, setPassword] = useState('');
  const [unlocking, setUnlocking] = useState(false);

  const handleUnlock = async () => {
    setUnlocking(true);
    try {
      await unlockKey(sessionKey.id, password);
      setPassword('');
    } finally {
      setUnlocking(false);
    }
  };

  const expiresIn = Math.max(0, sessionKey.expiry - Math.floor(Date.now() / 1000));
  const hours = Math.floor(expiresIn / 3600);
  const minutes = Math.floor((expiresIn % 3600) / 60);

  return (
    <div className={`key-card ${isUnlocked ? 'unlocked' : ''}`}>
      <div className="key-header">
        <span className="key-label">{sessionKey.label || 'Session Key'}</span>
        <span className={`key-status ${isUnlocked ? 'active' : ''}`}>
          {isUnlocked ? '🔓 Unlocked' : '🔒 Locked'}
        </span>
      </div>
      
      <div className="key-address">
        {sessionKey.address.slice(0, 8)}...{sessionKey.address.slice(-6)}
      </div>
      
      <div className="key-expiry">
        Expires in: {hours}h {minutes}m
      </div>
      
      <div className="key-scopes">
        {sessionKey.scopes.length} scopes delegated
      </div>
      
      {!isUnlocked ? (
        <div className="unlock-form">
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button onClick={handleUnlock} disabled={unlocking}>
            {unlocking ? 'Unlocking...' : 'Unlock'}
          </button>
        </div>
      ) : (
        <button onClick={lockKey} className="lock-btn">
          Lock Key
        </button>
      )}
      
      <button onClick={onDelete} className="delete-btn">
        Delete
      </button>
    </div>
  );
}

function SigningDemo() {
  const { unlockedKey, signMessage } = useSessionKey();
  const [message, setMessage] = useState('Hello, Symmio!');
  const [signature, setSignature] = useState('');
  const [signing, setSigning] = useState(false);

  const handleSign = async () => {
    setSigning(true);
    try {
      const sig = await signMessage(message);
      if (sig) setSignature(sig);
    } finally {
      setSigning(false);
    }
  };

  if (!unlockedKey) {
    return <p>Unlock a key to sign messages</p>;
  }

  return (
    <div className="signing-demo">
      <h3>Sign Message</h3>
      
      <textarea
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Enter message to sign"
      />
      
      <button onClick={handleSign} disabled={signing}>
        {signing ? 'Signing...' : 'Sign Message'}
      </button>
      
      {signature && (
        <div className="signature">
          <strong>Signature:</strong>
          <code>{signature}</code>
        </div>
      )}
    </div>
  );
}

// ========================================
// Main App Component
// ========================================

export function SessionKeyApp() {
  return (
    <SessionKeyProvider>
      <div className="session-key-app">
        <h1>Symmio Session Keys</h1>
        <CreateKeyForm />
        <KeyList />
        <SigningDemo />
      </div>
    </SessionKeyProvider>
  );
}

// CSS (would normally be in a separate file)
const styles = `
.session-key-app {
  max-width: 600px;
  margin: 0 auto;
  padding: 2rem;
  font-family: system-ui, -apple-system, sans-serif;
}

.create-key-form, .key-card, .signing-demo {
  background: #f8f9fa;
  padding: 1.5rem;
  border-radius: 12px;
  margin-bottom: 1rem;
}

.key-card.unlocked {
  background: #e8f5e9;
  border: 2px solid #4caf50;
}

.key-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 0.5rem;
}

.key-status.active {
  color: #4caf50;
}

input, textarea {
  width: 100%;
  padding: 0.75rem;
  margin-bottom: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 8px;
}

button {
  padding: 0.75rem 1.5rem;
  background: #2196f3;
  color: white;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  margin-right: 0.5rem;
}

button:disabled {
  opacity: 0.5;
}

.delete-btn {
  background: #f44336;
}

.lock-btn {
  background: #ff9800;
}

.error {
  color: #f44336;
}

.signature code {
  display: block;
  word-break: break-all;
  background: #eee;
  padding: 0.5rem;
  border-radius: 4px;
  margin-top: 0.5rem;
}
`;
