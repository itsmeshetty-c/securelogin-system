/**
 * Comprehensive Security & Functionality Test Suite
 */
const assert = require('assert');
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

async function runTests() {
  console.log('🧪 Starting Security & Authentication Test Suite...\n');

  let passed = 0;
  let failed = 0;

  function report(testName, success, details = '') {
    if (success) {
      console.log(`  ✅ PASS: ${testName}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${testName} - ${details}`);
      failed++;
    }
  }

  // Setup in-memory / temporary test database
  const testDbFile = path.join(__dirname, 'test.sqlite');
  if (fs.existsSync(testDbFile)) fs.unlinkSync(testDbFile);

  const testDb = new sqlite3.Database(testDbFile);

  await new Promise((resolve) => {
    testDb.serialize(() => {
      testDb.run(`
        CREATE TABLE users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          two_factor_enabled INTEGER DEFAULT 0,
          two_factor_secret TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_login DATETIME
        )
      `, resolve);
    });
  });

  const queryGet = (sql, params = []) => {
    return new Promise((resolve, reject) => {
      testDb.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
    });
  };

  const queryRun = (sql, params = []) => {
    return new Promise((resolve, reject) => {
      testDb.run(sql, params, function (err) {
        if (err) return reject(err);
        resolve({ lastID: this.lastID, changes: this.changes });
      });
    });
  };

  // TEST 1: Password Hashing with Bcrypt
  console.log('--- Feature 1: Password Hashing (bcrypt) ---');
  try {
    const rawPassword = 'SuperSecretPassword123!#';
    const hash = await bcrypt.hash(rawPassword, 12);

    report('Password is not stored in plaintext', hash !== rawPassword);
    report('Hash uses bcrypt format ($2a$ or $2b$)', hash.startsWith('$2a$') || hash.startsWith('$2b$'));

    const validMatch = await bcrypt.compare(rawPassword, hash);
    report('bcrypt.compare validates correct password', validMatch === true);

    const invalidMatch = await bcrypt.compare('WrongPassword456!', hash);
    report('bcrypt.compare rejects incorrect password', invalidMatch === false);
  } catch (err) {
    report('Bcrypt test execution', false, err.message);
  }

  // TEST 2: SQL Injection Defense via Parameterized Queries
  console.log('\n--- Feature 2: SQL Injection Protection ---');
  try {
    const testUsername = 'alice';
    const testEmail = 'alice@example.com';
    const testPassHash = await bcrypt.hash('SecurePass123!', 12);

    await queryRun(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [testUsername, testEmail, testPassHash]
    );

    // Attempt classic SQL Injection payloads
    const sqliPayload1 = "' OR 1=1 --";
    const sqliPayload2 = "admin' OR 'a'='a";
    const sqliPayload3 = "'; DROP TABLE users; --";

    const res1 = await queryGet('SELECT * FROM users WHERE username = ?', [sqliPayload1]);
    report('SQLi payload "\' OR 1=1 --" safely treated as literal string', res1 === undefined);

    const res2 = await queryGet('SELECT * FROM users WHERE username = ?', [sqliPayload2]);
    report('SQLi payload "admin\' OR \'a\'=\'a" safely treated as literal string', res2 === undefined);

    const res3 = await queryGet('SELECT * FROM users WHERE username = ?', [sqliPayload3]);
    report('SQLi payload "\'; DROP TABLE users; --" does not execute multi-statements', res3 === undefined);

    // Verify original table still exists and data intact
    const originalUser = await queryGet('SELECT * FROM users WHERE username = ?', [testUsername]);
    report('Legitimate user record intact after injection attempts', originalUser && originalUser.username === 'alice');
  } catch (err) {
    report('SQL injection test execution', false, err.message);
  }

  // TEST 3: Two-Factor Authentication (TOTP) Generation & Verification
  console.log('\n--- Feature 3: Two-Factor Authentication (TOTP) ---');
  try {
    const secret = authenticator.generateSecret();
    report('TOTP secret generated (Base32 format, length >= 16)', typeof secret === 'string' && secret.length >= 16);

    // Generate valid TOTP token for current timestamp
    const token = authenticator.generate(secret);
    report('TOTP token is 6 digits', /^\d{6}$/.test(token));

    const isValidToken = authenticator.verify({ token, secret });
    report('TOTP verify succeeds with valid current token', isValidToken === true);

    const isInvalidToken = authenticator.verify({ token: '999999', secret });
    report('TOTP verify fails with incorrect token', isInvalidToken === false);
  } catch (err) {
    report('2FA test execution', false, err.message);
  }

  // TEST 4: Input Validation Enforcement
  console.log('\n--- Feature 4: Input Validation ---');
  const validator = require('validator');

  const strongPass = 'P@ssw0rd2026!';
  const weakPass1 = 'simple';
  const weakPass2 = 'NoNumbersOrSymbols';

  report('Validates strong password correctly', validator.isStrongPassword(strongPass, { minLength: 8, minUppercase: 1, minNumbers: 1, minSymbols: 1 }));
  report('Rejects short password ("simple")', !validator.isStrongPassword(weakPass1, { minLength: 8 }));
  report('Rejects password lacking numbers & symbols', !validator.isStrongPassword(weakPass2, { minNumbers: 1, minSymbols: 1 }));
  report('Validates standard email address', validator.isEmail('test.user@domain.com'));
  report('Rejects invalid email format', !validator.isEmail('not-an-email@com'));

  // Cleanup
  testDb.close();
  if (fs.existsSync(testDbFile)) fs.unlinkSync(testDbFile);

  console.log(`\n========================================`);
  console.log(`Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Unhandled test failure:', err);
  process.exit(1);
});
