const db = require('../config/db');

class User {
  /**
   * Create a new user with hashed password.
   * Parameterized query protects against SQL injection.
   */
  static createUser({ username, email, passwordHash }) {
    const stmt = db.prepare(`
      INSERT INTO users (username, email, password_hash)
      VALUES (?, ?, ?)
    `);
    const result = stmt.run(username, email, passwordHash);
    return result.lastInsertRowid;
  }

  /**
   * Find user by username or email identifier.
   */
  static findByUsernameOrEmail(identifier) {
    const stmt = db.prepare(`
      SELECT * FROM users
      WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
    `);
    return stmt.get(identifier, identifier);
  }

  /**
   * Find user by unique ID.
   */
  static findById(id) {
    const stmt = db.prepare(`
      SELECT id, username, email, two_factor_secret, is_two_factor_enabled, created_at
      FROM users
      WHERE id = ?
    `);
    return stmt.get(id);
  }

  /**
   * Find user by email.
   */
  static findByEmail(email) {
    const stmt = db.prepare(`
      SELECT * FROM users WHERE LOWER(email) = LOWER(?)
    `);
    return stmt.get(email);
  }

  /**
   * Find user by username.
   */
  static findByUsername(username) {
    const stmt = db.prepare(`
      SELECT * FROM users WHERE LOWER(username) = LOWER(?)
    `);
    return stmt.get(username);
  }

  /**
   * Save temporary 2FA secret for activation setup.
   */
  static save2FASecret(userId, secret) {
    const stmt = db.prepare(`
      UPDATE users SET two_factor_secret = ? WHERE id = ?
    `);
    return stmt.run(secret, userId);
  }

  /**
   * Enable 2FA after successful code verification.
   */
  static enable2FA(userId) {
    const stmt = db.prepare(`
      UPDATE users SET is_two_factor_enabled = 1 WHERE id = ?
    `);
    return stmt.run(userId);
  }

  /**
   * Disable 2FA for user.
   */
  static disable2FA(userId) {
    const stmt = db.prepare(`
      UPDATE users SET is_two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?
    `);
    return stmt.run(userId);
  }
}

module.exports = User;
