import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { randomInt } from 'node:crypto';

export function openDatabase(filename = process.env.DATABASE_PATH || './data/bilin.sqlite') {
  if (filename !== ':memory:') mkdirSync(dirname(resolve(filename)), { recursive: true });
  const db = new DatabaseSync(filename);
  db.exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY, transfer_id TEXT NOT NULL UNIQUE CHECK(length(transfer_id)=4 AND transfer_id NOT GLOB '*[^0-9]*'),
      email TEXT UNIQUE COLLATE NOCASE, password_hash TEXT, nickname TEXT NOT NULL,
      phone TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', theme TEXT NOT NULL DEFAULT 'warm' CHECK(theme IN ('blue','green','warm')),
      internal_note TEXT NOT NULL DEFAULT '', created_by INTEGER,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE IF NOT EXISTS staff (
      id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
      name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin' CHECK(role IN ('admin','service'))
    );
    CREATE TABLE IF NOT EXISTS addresses (
      id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id),
      label TEXT NOT NULL DEFAULT '', recipient TEXT NOT NULL, phone TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
      country TEXT NOT NULL, province TEXT NOT NULL DEFAULT '', city TEXT NOT NULL,
      postcode TEXT NOT NULL DEFAULT '', street TEXT NOT NULL, extra TEXT NOT NULL DEFAULT '', is_default INTEGER NOT NULL DEFAULT 0
    );
    CREATE UNIQUE INDEX IF NOT EXISTS one_default_address ON addresses(customer_id) WHERE is_default=1;
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, customer_id INTEGER REFERENCES customers(id), staff_id INTEGER REFERENCES staff(id),
      csrf TEXT NOT NULL, expires_at INTEGER NOT NULL, authenticated_at INTEGER NOT NULL,
      CHECK((customer_id IS NOT NULL) != (staff_id IS NOT NULL))
    );
    CREATE TABLE IF NOT EXISTS wechat_identities (
      id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id),
      app_id TEXT NOT NULL, open_id TEXT NOT NULL, union_id TEXT,
      UNIQUE(app_id,open_id)
    );
    CREATE INDEX IF NOT EXISTS wechat_union ON wechat_identities(union_id);
    CREATE TABLE IF NOT EXISTS oauth_states (
      token_hash TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, mode TEXT NOT NULL,
      customer_id INTEGER REFERENCES customers(id), session_hash TEXT, expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY, actor_type TEXT NOT NULL, actor_id INTEGER, customer_id INTEGER,
      action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
  `);
  return db;
}

export function transaction(db, work) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = work(); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}

export function allocateTransferId(db) {
  const used = new Set(db.prepare('SELECT transfer_id FROM customers').all().map(row => row.transfer_id));
  if (used.size >= 10000) throw Object.assign(new Error('转运 ID 已全部分配，请联系管理员扩展编号规则'), { status: 409 });
  const available = [];
  for (let i = 0; i < 10000; i++) { const id = String(i).padStart(4, '0'); if (!used.has(id)) available.push(id); }
  return available[randomInt(available.length)];
}

export function createCustomer(db, input) {
  return transaction(db, () => {
    const id = allocateTransferId(db);
    const row = db.prepare('INSERT INTO customers(transfer_id,email,password_hash,nickname,phone,country,internal_note,created_by) VALUES(?,?,?,?,?,?,?,?) RETURNING *')
      .get(id, input.email || null, input.password_hash || null, input.nickname || '比邻客户', input.phone || '', input.country || '', input.internal_note || '', input.created_by || null);
    return row;
  });
}

export function publicCustomer(db, row) {
  if (!row) return null;
  return { id: row.id, transfer_id: row.transfer_id, nickname: row.nickname, email: row.email || '', phone: row.phone,
    country: row.country, theme: row.theme, created_at: row.created_at, updated_at: row.updated_at,
    has_password: Boolean(row.password_hash), wechat_bound: Boolean(db.prepare('SELECT id FROM wechat_identities WHERE customer_id=? LIMIT 1').get(row.id)) };
}

export const warehouse = transferId => ({ recipient: '比邻快递', phone: '13703907937',
  address: `河南省郑州市荥阳市豫龙镇五洲城一期${transferId}号二层驿收发`, transfer_id: transferId });
