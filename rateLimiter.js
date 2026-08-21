const rateLimit = require('express-rate-limit');

// Rate limiter for authentication endpoints (prevent brute-force password guessing & credential stuffing)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes window
  max: 10, // Max 10 failed/success attempts per IP per 15 minutes
  message: {
    success: false,
    message: 'Too many authentication attempts from this IP, please try again after 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter rate limiter for registration
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 15, // Max 15 accounts created per hour per IP
  message: {
    success: false,
    message: 'Too many accounts created from this IP. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = {
  authLimiter,
  registerLimiter
};
