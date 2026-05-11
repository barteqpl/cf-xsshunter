CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  pgp_key TEXT,
  path TEXT UNIQUE,
  injection_correlation_api_key TEXT UNIQUE,
  additional_js TEXT,
  send_email_alerts INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS payload_fire_results (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  encrypted INTEGER NOT NULL DEFAULT 0,
  encrypted_data TEXT,
  public_key TEXT,
  url TEXT,
  ip_address TEXT,
  referer TEXT,
  user_agent TEXT,
  cookies TEXT,
  title TEXT,
  origin TEXT,
  screenshot_id TEXT,
  was_iframe INTEGER,
  browser_timestamp INTEGER,
  git_exposed TEXT,
  cors TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  payload_id TEXT NOT NULL,
  secret_type TEXT NOT NULL,
  secret_value TEXT,
  FOREIGN KEY (payload_id) REFERENCES payload_fire_results(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collected_pages (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  uri TEXT NOT NULL,
  html TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS injection_requests (
  id TEXT PRIMARY KEY,
  request TEXT NOT NULL,
  injection_key TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_payload_results_user_id ON payload_fire_results(user_id);
CREATE INDEX IF NOT EXISTS idx_payload_results_ip ON payload_fire_results(ip_address);
CREATE INDEX IF NOT EXISTS idx_payload_results_origin ON payload_fire_results(origin);
CREATE INDEX IF NOT EXISTS idx_secrets_payload_id ON secrets(payload_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_path ON users(path);
CREATE INDEX IF NOT EXISTS idx_injection_key ON injection_requests(injection_key);
