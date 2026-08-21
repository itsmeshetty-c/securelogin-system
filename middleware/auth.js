// Middleware to verify that the request has an active authenticated session
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Active session required. Please log in.'
    });
  }

  // If user has 2FA enabled but has not verified the 2FA token for this session
  if (req.session.pendingTwoFactor) {
    return res.status(403).json({
      success: false,
      requires2FA: true,
      message: 'Two-Factor Authentication required to complete login.'
    });
  }

  next();
}

module.exports = {
  requireAuth
};
