/**
 * Authentication and Authorization Middlewares
 */

// Protect routes that require a fully authenticated user session
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) {
    return next();
  }
  req.flash('error', 'Please log in to access this page.');
  return res.redirect('/login');
};

// Prevent authenticated users from accessing login/register routes
const requireGuest = (req, res, next) => {
  if (req.session && req.session.userId) {
    return res.redirect('/dashboard');
  }
  return next();
};

// Require a pending 2FA authentication state during login
const require2FAPending = (req, res, next) => {
  if (req.session && req.session.pending2FAUserId) {
    return next();
  }
  req.flash('error', 'Session expired or 2FA step invalid. Please log in again.');
  return res.redirect('/login');
};

module.exports = {
  requireAuth,
  requireGuest,
  require2FAPending,
};
