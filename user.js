const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const validator = require('validator');
const db = require('../database');
const { requireAuth } = require('../middleware/auth');

/**
 * Helper: Validate password strength
 */
function validatePassword(password) {
  if (!password || typeof password !== 'string') return false;
  return validator.isStrongPassword(password, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1
  });
}

/**
 * GET /api/user/logs
 * Retrieve recent security audit logs for the authenticated user
 */
router.get('/logs', requireAuth, async (req, res) => {
  try {
    const logs = await db.all(
      'SELECT event_type, ip_address, user_agent, details, created_at FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
      [req.session.userId]
    );

    return res.json({ success: true, logs });
  } catch (error) {
    console.error('Audit log fetch error:', error);
    return res.status(500).json({ success: false, message: 'Failed to retrieve security logs.' });
  }
});

/**
 * POST /api/user/change-password
 * Change password with current password verification and strength enforcement
 */
router.post('/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Current password and new password are required.' });
    }

    if (!validatePassword(newPassword)) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 8 characters long and contain uppercase, lowercase, numbers, and symbols.'
      });
    }

    const user = await db.get('SELECT id, password_hash FROM users WHERE id = ?', [req.session.userId]);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isMatch) {
      await db.logSecurityEvent(user.id, 'PASSWORD_CHANGE_FAILED', ip, userAgent, 'Incorrect current password provided.');
      return res.status(400).json({ success: false, message: 'Incorrect current password.' });
    }

    const newHash = await bcrypt.hash(newPassword, 12);
    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, user.id]);

    await db.logSecurityEvent(user.id, 'PASSWORD_CHANGED', ip, userAgent, 'User password successfully updated.');

    return res.json({ success: true, message: 'Password updated successfully!' });
  } catch (error) {
    console.error('Password change error:', error);
    return res.status(500).json({ success: false, message: 'Failed to update password.' });
  }
});

module.exports = router;
