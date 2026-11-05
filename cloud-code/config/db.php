<?php

if (!is_file(__DIR__ . '/config.php')) {
    throw new RuntimeException('Database configuration is missing. Run install.php first.');
}

$config = require __DIR__ . '/config.php';
$databasePath = $config['database_path'] ?? null;
if (!is_string($databasePath) || $databasePath === '') {
    throw new RuntimeException('The database_path setting is missing or invalid.');
}

$pdo = new PDO('sqlite:' . $databasePath);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('PRAGMA foreign_keys = ON');

$pdo->exec("
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        totp_secret TEXT,
        api_token TEXT,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY NOT NULL,
        name TEXT NOT NULL,
        device_token TEXT NOT NULL UNIQUE,
        last_payload TEXT,
        last_update DATETIME
    );

    CREATE TABLE IF NOT EXISTS user_devices (
        user_id INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        permission TEXT DEFAULT 'read',
        PRIMARY KEY (user_id, device_id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (device_id) REFERENCES devices (id)
    );

    CREATE INDEX IF NOT EXISTS idx_user_devices_device_id
        ON user_devices (device_id);

    CREATE TABLE IF NOT EXISTS device_history_settings (
        device_id TEXT PRIMARY KEY NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
        interval_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (interval_seconds > 0),
        retention_seconds INTEGER NOT NULL DEFAULT 604800 CHECK (retention_seconds > 0),
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
    );

    CREATE TRIGGER IF NOT EXISTS trg_devices_default_history_settings
    AFTER INSERT ON devices
    BEGIN
        INSERT OR IGNORE INTO device_history_settings (device_id, enabled)
        VALUES (NEW.id, 0);
    END;
");

$userColumns = $pdo->query('PRAGMA table_info(users)')->fetchAll(PDO::FETCH_COLUMN, 1);
if (!in_array('api_token', $userColumns, true)) {
    $pdo->exec('ALTER TABLE users ADD COLUMN api_token TEXT');
}
$pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_token ON users (api_token)');
$pdo->exec(
    'INSERT OR IGNORE INTO device_history_settings (device_id, enabled) '
    . 'SELECT id, 0 FROM devices'
);
