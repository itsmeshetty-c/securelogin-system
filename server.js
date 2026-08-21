require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'secure-login-super-secret-key-32chars!';

// 1. Security Headers with Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

// 2. Request body parsing
app.use(express.json({ limit: '10kb' })); // Protection against large payload DOS
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 3. Secure Session Management
app.use(
  session({
    secret: SESSION_SECRET,
    name: 'sessionId', // Custom cookie name to obscure tech stack
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevents client-side JS access to cookie (XSS protection)
      secure: process.env.NODE_ENV === 'production', // true if served over HTTPS
      sameSite: 'lax', // CSRF mitigation
      maxAge: 2 * 60 * 60 * 1000 // 2 hours session expiry
    }
  })
);

// 4. Static files serving
app.use(express.static(path.join(__dirname, 'public')));

// 5. Mount API Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

// 6. SPA fallback routes
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 7. Global Centralized Error Handling
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err);
  res.status(500).json({
    success: false,
    message: 'An unexpected server error occurred.'
  });
});

// 8. Start server
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`🛡️  Secure Login Web Application running!`);
    console.log(`🌐 Local URL: http://localhost:${PORT}`);
    console.log(`🔒 Hashed Passwords: bcrypt (12 rounds)`);
    console.log(`🛡️  SQL Injection Protection: Parameterized Queries`);
    console.log(`🔑 Two-Factor Authentication (2FA): TOTP Enabled`);
    console.log(`====================================================`);
  });
}

module.exports = app;
