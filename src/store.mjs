import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdirSync, chmodSync, lstatSync } from 'node:fs';
import { dirname } from 'node:path';
export const secret = () => randomBytes(32).toString('base64url');
export const digest = value => createHash('sha256').update(value).digest('hex');

// All values are authenticated encrypted; token lookup keys are SHA256 digests.
// One process owns this database. Transactions deliberately contain no awaits.
export class Store {
  constructor(path, key) {
    if (!/^[a-fA-F0-9]{64}$/.test(key || '')) throw new Error('MCP_STORAGE_KEY must be 32 random bytes encoded as hex');
    this.key = Buffer.from(key, 'hex');
    if (path !== ':memory:') {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      const parent = lstatSync(dirname(path));
      if (parent.isSymbolicLink() || parent.uid !== process.getuid() || (parent.mode & 0o077)) throw new Error('State directory must be owned by this user and mode 0700');
    }
    this.db = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec('PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON; CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, expiry INTEGER NOT NULL, PRIMARY KEY(kind,id));');
  }
  seal(kind, id, value) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(`${kind}:${id}`));
    const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
  }
  open(kind, id, data) {
    const bytes = Buffer.from(data, 'base64');
    const cipher = createDecipheriv('aes-256-gcm', this.key, bytes.subarray(0, 12));
    cipher.setAAD(Buffer.from(`${kind}:${id}`));
    cipher.setAuthTag(bytes.subarray(12, 28));
    return JSON.parse(Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString());
  }
  put(kind, id, value, expiry) {
    this.db.prepare('INSERT OR REPLACE INTO records VALUES (?,?,?,?)').run(kind, id, this.seal(kind, id, value), expiry);
  }
  get(kind, id) {
    if (typeof id !== 'string') return null;
    const row = this.db.prepare('SELECT value,expiry FROM records WHERE kind=? AND id=?').get(kind, id);
    return row && row.expiry > Date.now() ? this.open(kind, id, row.value) : null;
  }
  delete(kind, id) { this.db.prepare('DELETE FROM records WHERE kind=? AND id=?').run(kind, id); }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); this.db.exec('COMMIT'); return result; }
    catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  // Removes and returns expired records of one kind, for cleanup that must act on them first.
  takeExpired(kind) {
    const now = Date.now();
    return this.transaction(() => {
      const rows = this.db.prepare('SELECT id,value FROM records WHERE kind=? AND expiry <= ?').all(kind, now);
      this.db.prepare('DELETE FROM records WHERE kind=? AND expiry <= ?').run(kind, now);
      return rows.map(row => ({ id: row.id, value: this.open(kind, row.id, row.value) }));
    });
  }
  // Kinds in `except` are left for a takeExpired() owner that must act on them before deletion.
  prune({ except = [] } = {}) {
    this.db.prepare(`DELETE FROM records WHERE expiry <= ? AND kind NOT IN (${except.map(() => '?').join(',') || "''"})`).run(Date.now(), ...except);
  }
  close() { this.db.close(); }
}
