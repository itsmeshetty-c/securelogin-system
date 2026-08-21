const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const dbPath = process.env.DB_PATH || 'database.sqlite';
const dbFile = path.isAbsolute(dbPath) ? dbPath : path.join(__dirname, '..', dbPath);

// Initialize SQLite Database using Node.js built-in DatabaseSync engine
const db = new DatabaseSync(dbFile);

// Initialize Database Schema
const initSchema = () => {
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      two_factor_secret TEXT DEFAULT NULL,
      is_two_factor_enabled INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `;
  db.exec(createUsersTable);
  console.log('[DATABASE] SQLite schema initialized successfully.');
};

initSchema();

module.exports = db;
