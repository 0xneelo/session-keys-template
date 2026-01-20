/**
 * Storage adapters for session key persistence
 * Supports IndexedDB (preferred), localStorage fallback, and custom adapters
 */

import type { StorageAdapter, StoredSessionKey } from './types';

const DB_NAME = 'symmio-session-keys';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

/**
 * IndexedDB storage adapter (preferred for browser)
 */
export class IndexedDBStorage implements StorageAdapter {
  private db: IDBDatabase | null = null;
  private initPromise: Promise<void> | null = null;

  private async init(): Promise<void> {
    if (this.db) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = () => {
        reject(new Error('Failed to open IndexedDB'));
      };

      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      };
    });

    return this.initPromise;
  }

  async get(key: string): Promise<string | null> {
    await this.init();
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(key);

      request.onerror = () => reject(new Error('Failed to read from IndexedDB'));
      request.onsuccess = () => resolve(request.result || null);
    });
  }

  async set(key: string, value: string): Promise<void> {
    await this.init();
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.put(value, key);

      request.onerror = () => reject(new Error('Failed to write to IndexedDB'));
      request.onsuccess = () => resolve();
    });
  }

  async delete(key: string): Promise<void> {
    await this.init();
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.delete(key);

      request.onerror = () => reject(new Error('Failed to delete from IndexedDB'));
      request.onsuccess = () => resolve();
    });
  }

  async keys(): Promise<string[]> {
    await this.init();
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.getAllKeys();

      request.onerror = () => reject(new Error('Failed to get keys from IndexedDB'));
      request.onsuccess = () => resolve(request.result as string[]);
    });
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
      this.initPromise = null;
    }
  }
}

/**
 * localStorage fallback adapter
 */
export class LocalStorageAdapter implements StorageAdapter {
  private prefix = 'symmio-sk-';

  async get(key: string): Promise<string | null> {
    const value = localStorage.getItem(this.prefix + key);
    return value;
  }

  async set(key: string, value: string): Promise<void> {
    localStorage.setItem(this.prefix + key, value);
  }

  async delete(key: string): Promise<void> {
    localStorage.removeItem(this.prefix + key);
  }

  async keys(): Promise<string[]> {
    const keys: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(this.prefix)) {
        keys.push(key.slice(this.prefix.length));
      }
    }
    return keys;
  }
}

/**
 * In-memory storage adapter (for testing or non-persistent use)
 */
export class MemoryStorage implements StorageAdapter {
  private store = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) || null;
  }

  async set(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async keys(): Promise<string[]> {
    return Array.from(this.store.keys());
  }

  clear(): void {
    this.store.clear();
  }
}

/**
 * Creates the best available storage adapter
 */
export function createStorage(): StorageAdapter {
  // Check for IndexedDB support
  if (typeof indexedDB !== 'undefined') {
    return new IndexedDBStorage();
  }
  
  // Fallback to localStorage
  if (typeof localStorage !== 'undefined') {
    return new LocalStorageAdapter();
  }
  
  // Last resort: memory storage
  return new MemoryStorage();
}

/**
 * Session key storage helper
 */
export class SessionKeyStorage {
  private adapter: StorageAdapter;
  private keyPrefix = 'session-key-';

  constructor(adapter?: StorageAdapter) {
    this.adapter = adapter || createStorage();
  }

  private getStorageKey(keyId: string): string {
    return this.keyPrefix + keyId;
  }

  async save(key: StoredSessionKey): Promise<void> {
    const storageKey = this.getStorageKey(key.id);
    await this.adapter.set(storageKey, JSON.stringify(key));
  }

  async load(keyId: string): Promise<StoredSessionKey | null> {
    const storageKey = this.getStorageKey(keyId);
    const data = await this.adapter.get(storageKey);
    if (!data) return null;
    
    try {
      return JSON.parse(data) as StoredSessionKey;
    } catch {
      return null;
    }
  }

  async remove(keyId: string): Promise<void> {
    const storageKey = this.getStorageKey(keyId);
    await this.adapter.delete(storageKey);
  }

  async listAll(): Promise<StoredSessionKey[]> {
    const allKeys = await this.adapter.keys();
    const sessionKeys: StoredSessionKey[] = [];

    for (const key of allKeys) {
      if (key.startsWith(this.keyPrefix)) {
        const keyId = key.slice(this.keyPrefix.length);
        const sessionKey = await this.load(keyId);
        if (sessionKey) {
          sessionKeys.push(sessionKey);
        }
      }
    }

    return sessionKeys;
  }

  async listValid(): Promise<StoredSessionKey[]> {
    const all = await this.listAll();
    const now = Date.now();
    return all.filter((key) => key.expiry * 1000 > now);
  }

  async listExpired(): Promise<StoredSessionKey[]> {
    const all = await this.listAll();
    const now = Date.now();
    return all.filter((key) => key.expiry * 1000 <= now);
  }

  async clearExpired(): Promise<string[]> {
    const expired = await this.listExpired();
    const removedIds: string[] = [];
    
    for (const key of expired) {
      await this.remove(key.id);
      removedIds.push(key.id);
    }
    
    return removedIds;
  }

  async clearAll(): Promise<void> {
    const all = await this.listAll();
    for (const key of all) {
      await this.remove(key.id);
    }
  }
}
