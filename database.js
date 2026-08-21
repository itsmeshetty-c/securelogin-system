const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to connect to SQLite database:', err.message);
  } else {
    console.log('Connected to SQLite database at', dbPath);
  }
});

// Enable foreign key constraints and WAL mode for better concurrency
db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON;');
  db.run('PRAGMA journal_mode = WAL;');

  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      two_factor_enabled INTEGER DEFAULT 0,
      two_factor_secret TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    )
  `);

  // Ensure any missing columns are added if an older table schema exists
  db.all("PRAGMA table_info(users)", (err, columns) => {
    if (!err && columns) {
      const colNames = columns.map(c => c.name);
      if (!colNames.includes('last_login')) {
        db.run("ALTER TABLE users ADD COLUMN last_login DATETIME");
      }
      if (!colNames.includes('two_factor_enabled')) {
        if (colNames.includes('is_two_factor_enabled')) {
          db.run("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0");
          db.run("UPDATE users SET two_factor_enabled = is_two_factor_enabled");
        } else {
          db.run("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0");
        }
      }
      if (!colNames.includes('two_factor_secret')) {
        db.run("ALTER TABLE users ADD COLUMN two_factor_secret TEXT");
      }
    }
  });

  // Security audit logs table
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      event_type TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
  `);
});

// Helper promise-based methods with parameterized queries to prevent SQL injection
const dbHelper = {
  get: (sql, params = []) => {
    return new Promise((resolve, reject) => {
      db.get(sql, params, (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });
  },

  run: (sql, params = []) => {
    return new Promise((resolve, reject) => {
      db.run(sql, params, function (err) {
        if (err) return reject(err);
        resolve({ lastID: this.lastID, changes: this.changes });
      });
    });
  },

  all: (sql, params = []) => {
    return new Promise((resolve, reject) => {
      db.all(sql, params, (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      });
    });
  },

  logSecurityEvent: async (userId, eventType, ip, userAgent, details) => {
    try {
      await dbHelper.run(
        `INSERT INTO audit_logs (user_id, event_type, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)`,
        [userId || null, eventType, ip || 'unknown', userAgent || 'unknown', details || '']
      );
    } catch (err) {
      console.error('Failed to log security event:', err.message);
    }
  },

  rawDb: db
};

module.exports = dbHelper;
