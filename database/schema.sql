-- ============================================================
-- Khokhar & Son's Antivirus - SQLite schema
-- All access goes through database/database.py using
-- parameterized queries. Never concatenate user input into SQL.
-- ============================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------
-- settings : persisted application settings (JSON values)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ------------------------------------------------------------
-- scan_history : one row per scan session
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type       TEXT    NOT NULL,             -- quick | full | custom | usb | realtime
    start_time      TEXT    NOT NULL,
    end_time        TEXT,
    files_scanned   INTEGER NOT NULL DEFAULT 0,
    directories_scanned INTEGER NOT NULL DEFAULT 0,
    threats_found   INTEGER NOT NULL DEFAULT 0,
    suspicious_found INTEGER NOT NULL DEFAULT 0,
    quarantined     INTEGER NOT NULL DEFAULT 0,
    skipped         INTEGER NOT NULL DEFAULT 0,
    errors          INTEGER NOT NULL DEFAULT 0,
    duration_secs   REAL,
    status          TEXT    NOT NULL DEFAULT 'running',  -- running | completed | stopped | failed
    scan_targets    TEXT,                          -- JSON array of paths
    CONSTRAINT chk_scan_type CHECK (scan_type IN ('quick','full','custom','usb','realtime'))
);

-- ------------------------------------------------------------
-- scan_results : per-file results belonging to a scan
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results (
    result_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scan_history(scan_id) ON DELETE CASCADE,
    file_path       TEXT    NOT NULL,
    sha256          TEXT,
    file_size       INTEGER,
    detection_name  TEXT,
    detection_type  TEXT,        -- signature | heuristic | yara | pe | archive
    severity        TEXT,        -- clean | low | medium | high | critical
    confidence      TEXT,        -- low | medium | high
    risk_score      INTEGER,
    reason          TEXT,
    recommended_action TEXT,
    action_taken    TEXT,        -- none | quarantined | user_allowed | error
    detected_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_sha256  ON scan_results(sha256);

-- ------------------------------------------------------------
-- threats : standalone threat detections (incl. realtime/usb)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threats (
    threat_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path       TEXT    NOT NULL,
    sha256          TEXT,
    file_size       INTEGER,
    detection_name  TEXT    NOT NULL,
    detection_type  TEXT,
    severity        TEXT,
    confidence      TEXT,
    risk_score      INTEGER,
    reason          TEXT,
    recommended_action TEXT,
    source          TEXT,        -- scan | usb | realtime
    scan_id         INTEGER REFERENCES scan_history(scan_id) ON DELETE SET NULL,
    status          TEXT    NOT NULL DEFAULT 'open',   -- open | quarantined | allowed | deleted
    detected_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    resolved_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);

-- ------------------------------------------------------------
-- quarantine : records for isolated files
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS quarantine (
    quarantine_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path   TEXT    NOT NULL,
    quarantine_path TEXT    NOT NULL,
    sha256          TEXT,
    detection_name  TEXT,
    detection_type  TEXT,
    severity        TEXT,
    file_size       INTEGER,
    quarantine_date TEXT    NOT NULL DEFAULT (datetime('now')),
    restored_date   TEXT,
    deleted_date    TEXT,
    status          TEXT    NOT NULL DEFAULT 'QUARANTINED', -- QUARANTINED | RESTORED | DELETED
    metadata        TEXT    -- JSON: extra file metadata
);

CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);

-- ------------------------------------------------------------
-- security_events : audit log of security-relevant events
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT    NOT NULL,   -- usb_inserted, scan_started, threat_detected, ...
    severity        TEXT    NOT NULL DEFAULT 'info', -- info | warning | critical
    description     TEXT,
    details         TEXT,               -- JSON payload
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(created_at);

-- ------------------------------------------------------------
-- signatures : updatable local signature database
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS signatures (
    signature_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT    NOT NULL UNIQUE,
    name            TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    category        TEXT,
    description     TEXT,
    source          TEXT    NOT NULL DEFAULT 'local',   -- local | update
    added_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_signatures_sha256 ON signatures(sha256);

-- ------------------------------------------------------------
-- exclusions : user-configured scan exclusions
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exclusions (
    exclusion_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    exclusion_type  TEXT    NOT NULL,   -- file | folder | extension | hash
    value           TEXT    NOT NULL,
    label           TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (exclusion_type, value)
);

-- ------------------------------------------------------------
-- usb_devices : seen removable devices
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usb_devices (
    device_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    drive_letter    TEXT    NOT NULL,
    volume_name     TEXT,
    serial          TEXT,
    capacity_bytes  INTEGER,
    free_bytes      INTEGER,
    file_system     TEXT,
    last_scan_id    INTEGER REFERENCES scan_history(scan_id) ON DELETE SET NULL,
    last_seen       TEXT    NOT NULL DEFAULT (datetime('now')),
    last_scan_time  TEXT,
    last_scan_status TEXT,             -- not_scanned | clean | threats_found
    UNIQUE (drive_letter, serial)
);

-- ------------------------------------------------------------
-- cleanup_history : records of cleanup operations for recovery
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cleanup_history (
    cleanup_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cleanup_type    TEXT    NOT NULL,   -- startup_entry | scheduled_task | service | file
    target          TEXT    NOT NULL,
    backup_data     TEXT,               -- JSON snapshot allowing restore
    description     TEXT,
    performed_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    restored        INTEGER NOT NULL DEFAULT 0,
    restored_at     TEXT
);

-- ------------------------------------------------------------
-- usb_trusted_devices : user-approved removable drives that skip
-- automatic rescanning. Trust is by volume serial + label, so a
-- different drive with the same letter is never trusted by accident.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usb_trusted_devices (
    device_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    serial          TEXT    NOT NULL,
    volume_name     TEXT    NOT NULL,
    label           TEXT,
    trusted_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (serial, volume_name)
);
