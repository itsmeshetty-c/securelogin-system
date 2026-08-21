const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const validator = require('validator');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const db = require('../database');
const { authLimiter, registerLimiter } = require('../middleware/rateLimiter');
const { requireAuth } = require('../middleware/auth');

// Configure OTPLib
authenticator.options = { window: 1 }; // Allow 1 step drift (+/- 30 seconds)

/**
 * Helper: Validate password strength
 * Requires >= 8 chars, at least 1 uppercase, 1 lowercase, 1 digit, and 1 special char
 */
function validatePassword(password) {
  if (!password || typeof password !== 'string') return false;
  const isStrong = validator.isStrongPassword(password, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1
  });
  return isStrong;
}

/**
 * POST /api/auth/register
 * Register a new user with bcrypt password hashing
 */
router.post('/register', registerLimiter, async (req, res) => {
  try {
    let { username, email, password } = req.body;

    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    // 1. Sanitize and validate inputs
    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    username = String(username).trim();
    email = String(email).trim().toLowerCase();

    if (!validator.isAlphanumeric(username, 'en-US', { ignore: '_-' }) || username.length < 3 || username.length > 30) {
      return res.status(400).json({
        success: false,
        message: 'Username must be between 3 and 30 characters and contain only letters, numbers, hyphens, or underscores.'
      });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.'
      });
    }

    // 2. Check if username or email already exists (using parameterized query)
    const existingUser = await db.get(
      'SELECT id, username, email FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUser) {
      const field = existingUser.username.toLowerCase() === username.toLowerCase() ? 'Username' : 'Email';
      return res.status(409).json({ success: false, message: `${field} is already registered.` });
    }

    // 3. Hash password with bcrypt (salt factor 12)
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // 4. Save user to database (Parameterized query to prevent SQL Injection)
    const result = await db.run(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, passwordHash]
    );

    await db.logSecurityEvent(result.lastID, 'USER_REGISTERED', ip, userAgent, `User ${username} registered successfully.`);

    return res.status(201).json({
      success: true,
      message: 'Registration successful! You can now log in.'
    });

  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error during registration.' });
  }
});

/**
 * POST /api/auth/login
 * User login with session management and optional 2FA check
 */
router.post('/login', authLimiter, async (req, res) => {
  try {
    let { identifier, password } = req.body; // identifier can be username or email

    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!identifier || !password) {
      return res.status(400).json({ success: false, message: 'Please provide both username/email and password.' });
    }

    identifier = String(identifier).trim();

    // 1. Fetch user by username OR email (Parameterized query)
    const user = await db.get(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [identifier, identifier.toLowerCase()]
    );

    if (!user) {
      await db.logSecurityEvent(null, 'LOGIN_FAILED', ip, userAgent, `Failed attempt for identifier: ${identifier}`);
      // Generic message to prevent user enumeration
      return res.status(401).json({ success: false, message: 'Invalid username/email or password.' });
    }

    // 2. Compare password hash
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      await db.logSecurityEvent(user.id, 'LOGIN_FAILED', ip, userAgent, 'Invalid password attempt.');
      return res.status(401).json({ success: false, message: 'Invalid username/email or password.' });
    }

    // 3. Prevent Session Fixation: Regenerate session ID upon successful credential verification
    req.session.regenerate(async (err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).json({ success: false, message: 'Failed to initialize secure session.' });
      }

      // 4. Handle 2FA check
      if (user.two_factor_enabled) {
        // Store temporary verification state in session
        req.session.tempUserId = user.id;
        req.session.pendingTwoFactor = true;

        await db.logSecurityEvent(user.id, 'LOGIN_2FA_CHALLENGE', ip, userAgent, '2FA challenge prompted.');

        return res.json({
          success: true,
          requires2FA: true,
          message: 'Two-Factor Authentication is enabled. Please enter your 6-digit authenticator code.'
        });
      }

      // If 2FA is NOT enabled, complete login immediately
      req.session.userId = user.id;
      req.session.pendingTwoFactor = false;

      // Update last login timestamp
      await db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
      await db.logSecurityEvent(user.id, 'LOGIN_SUCCESS', ip, userAgent, 'User logged in successfully.');

      return res.json({
        success: true,
        requires2FA: false,
        message: 'Login successful!',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          twoFactorEnabled: false
        }
      });
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error during login.' });
  }
});

/**
 * POST /api/auth/verify-2fa-login
 * Complete login for 2FA-enabled accounts
 */
router.post('/verify-2fa-login', authLimiter, async (req, res) => {
  try {
    const { token } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!req.session.tempUserId || !req.session.pendingTwoFactor) {
      return res.status(400).json({ success: false, message: 'No pending 2FA login session found. Please log in again.' });
    }

    if (!token || String(token).trim().length !== 6) {
      return res.status(400).json({ success: false, message: 'Please enter a valid 6-digit 2FA code.' });
    }

    const user = await db.get('SELECT * FROM users WHERE id = ?', [req.session.tempUserId]);
    if (!user || !user.two_factor_secret) {
      return res.status(400).json({ success: false, message: 'Invalid 2FA state.' });
    }

    const isValidToken = authenticator.verify({
      token: String(token).trim(),
      secret: user.two_factor_secret
    });

    if (!isValidToken) {
      await db.logSecurityEvent(user.id, '2FA_VERIFY_FAILED', ip, userAgent, 'Incorrect 2FA code entered.');
      return res.status(401).json({ success: false, message: 'Invalid 2FA verification code. Please try again.' });
    }

    // Successfully verified 2FA
    const completedUserId = req.session.tempUserId;
    delete req.session.tempUserId;
    req.session.pendingTwoFactor = false;
    req.session.userId = completedUserId;

    await db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [completedUserId]);
    await db.logSecurityEvent(completedUserId, 'LOGIN_2FA_SUCCESS', ip, userAgent, '2FA verification succeeded. Login complete.');

    return res.json({
      success: true,
      message: 'Two-Factor Authentication verified. Login successful!',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        twoFactorEnabled: true
      }
    });

  } catch (error) {
    console.error('2FA login verification error:', error);
    return res.status(500).json({ success: false, message: 'Error verifying 2FA.' });
  }
});

/**
 * GET /api/auth/me
 * Check current active session
 */
router.get('/me', requireAuth, async (req, res) => {
  try {
    const user = await db.get(
      'SELECT id, username, email, two_factor_enabled, created_at, last_login FROM users WHERE id = ?',
      [req.session.userId]
    );

    if (!user) {
      req.session.destroy();
      return res.status(401).json({ success: false, message: 'User not found.' });
    }

    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        twoFactorEnabled: Boolean(user.two_factor_enabled),
        createdAt: user.created_at,
        lastLogin: user.last_login
      }
    });
  } catch (error) {
    console.error('Session check error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

/**
 * POST /api/auth/2fa/generate
 * Generate 2FA secret and QR code for user to scan
 */
router.post('/2fa/generate', requireAuth, async (req, res) => {
  try {
    const user = await db.get('SELECT id, username, email FROM users WHERE id = ?', [req.session.userId]);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const secret = authenticator.generateSecret();
    const otpAuthUrl = authenticator.keyuri(user.email, 'SecureLoginSystem', secret);
    const qrCodeDataUrl = await qrcode.toDataURL(otpAuthUrl);

    // Save temporary setup secret in session until confirmed with a valid token
    req.session.setupTwoFactorSecret = secret;

    return res.json({
      success: true,
      secret,
      qrCodeDataUrl
    });
  } catch (error) {
    console.error('2FA generate error:', error);
    return res.status(500).json({ success: false, message: 'Failed to generate 2FA secret.' });
  }
});

/**
 * POST /api/auth/2fa/enable
 * Confirm and enable 2FA after scanning QR code
 */
router.post('/2fa/enable', requireAuth, async (req, res) => {
  try {
    const { token } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!req.session.setupTwoFactorSecret) {
      return res.status(400).json({ success: false, message: 'Please request a 2FA setup first.' });
    }

    const secret = req.session.setupTwoFactorSecret;
    const isValid = authenticator.verify({ token: String(token).trim(), secret });

    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid 6-digit code. Please verify and try again.' });
    }

    // Save 2FA secret in DB and enable 2FA
    await db.run(
      'UPDATE users SET two_factor_enabled = 1, two_factor_secret = ? WHERE id = ?',
      [secret, req.session.userId]
    );

    delete req.session.setupTwoFactorSecret;

    await db.logSecurityEvent(req.session.userId, '2FA_ENABLED', ip, userAgent, 'Two-Factor Authentication enabled.');

    return res.json({
      success: true,
      message: 'Two-Factor Authentication has been successfully enabled for your account!'
    });
  } catch (error) {
    console.error('2FA enable error:', error);
    return res.status(500).json({ success: false, message: 'Failed to enable 2FA.' });
  }
});

/**
 * POST /api/auth/2fa/disable
 * Disable 2FA with password confirmation
 */
router.post('/2fa/disable', requireAuth, async (req, res) => {
  try {
    const { password, token } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!password) {
      return res.status(400).json({ success: false, message: 'Password is required to disable 2FA.' });
    }

    const user = await db.get('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Incorrect password.' });
    }

    if (token) {
      const isValid = authenticator.verify({ token: String(token).trim(), secret: user.two_factor_secret });
      if (!isValid) {
        return res.status(400).json({ success: false, message: 'Invalid 2FA code.' });
      }
    }

    await db.run('UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?', [req.session.userId]);
    await db.logSecurityEvent(req.session.userId, '2FA_DISABLED', ip, userAgent, 'Two-Factor Authentication disabled.');

    return res.json({
      success: true,
      message: 'Two-Factor Authentication has been disabled.'
    });
  } catch (error) {
    console.error('2FA disable error:', error);
    return res.status(500).json({ success: false, message: 'Failed to disable 2FA.' });
  }
});

/**
 * POST /api/auth/logout
 * Destroy session and clear session cookie
 */
router.post('/logout', (req, res) => {
  const userId = req.session ? req.session.userId : null;
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'] || 'Unknown';

  if (req.session) {
    req.session.destroy(async (err) => {
      if (err) {
        console.error('Logout error:', err);
        return res.status(500).json({ success: false, message: 'Could not log out. Please try again.' });
      }

      if (userId) {
        await db.logSecurityEvent(userId, 'USER_LOGOUT', ip, userAgent, 'User logged out.');
      }

      res.clearCookie('connect.sid', { path: '/' });
      return res.json({ success: true, message: 'Logged out successfully.' });
    });
  } else {
    return res.json({ success: true, message: 'No active session.' });
  }
});

module.exports = router;
