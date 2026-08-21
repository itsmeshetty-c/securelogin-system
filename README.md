# 🛡️ Secure Login System Web Application

A robust, enterprise-grade authentication web application built with **Node.js**, **Express**, **SQLite**, and **Tailwind CSS**.

---

## 🌟 Key Features & Requirements Met

| Requirement | Implementation Details |
| :--- | :--- |
| **Password Hashing** | Uses **`bcryptjs`** with **12 salt rounds**. Passwords are never stored in plain text. |
| **SQL Injection Protection** | **100% Parameterized Prepared Statements** across all database queries. |
| **Input Validation** | Strict sanitization and validation using `validator` for usernames, emails, and passwords. |
| **Session Management** | Secure `express-session` with **`httpOnly`**, **`sameSite: lax`**, session fixation prevention, and a clean logout feature. |
| **Two-Factor Authentication (2FA)** | **TOTP (RFC 6238)** integration with QR code scanning for Google Authenticator, Microsoft Authenticator, and Authy. |
| **Brute-Force & Rate Limiting** | `express-rate-limit` prevents brute-force login attempts and automated account creation. |
| **Security Audit Logs** | Records security events (registrations, logins, 2FA activations, password updates, failures) with IP & timestamp. |

---

## 🚀 Getting Started

### 1. Prerequisites
- **Node.js** (v16 or higher)
- **npm**

### 2. Installation
Open a terminal in this directory (`C:\Users\ASUS\.gemini\antigravity\scratch\secure-login-system`) and run:
```bash
npm install
```

### 3. Start the Application
```bash
npm start
```
Then open your browser at:
👉 **[http://localhost:3000](http://localhost:3000)**

### 4. Run Automated Security Tests
```bash
npm test
```

---

## 📁 Project Structure

```
secure-login-system/
├── database.js               # SQLite connection & parameterized helper methods
├── server.js                 # Express app, Helmet headers, session & routing
├── middleware/
│   ├── auth.js               # Session validation and 2FA verification guard
│   └── rateLimiter.js        # Brute-force protection middleware
├── routes/
│   ├── auth.js               # Register, Login, 2FA setup, verify, and logout
│   └── user.js               # User profile, password change & audit logs
├── public/
│   ├── css/
│   │   └── styles.css        # Glassmorphism styling and custom animations
│   ├── js/
│   │   ├── auth.js           # Client-side validation, password strength meter, 2FA challenge
│   │   └── dashboard.js      # Dashboard state, 2FA QR modal, logs rendering
│   ├── index.html            # Sign in, Sign up, and 2FA challenge UI
│   └── dashboard.html        # Secure dashboard with user profile & security controls
├── test/
│   └── security.test.js      # Comprehensive security and authentication test suite
└── package.json              # Project dependencies and test scripts
```

---

## 🔒 Security Architecture Highlights

1. **Password Policy Enforcement**: Requires minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 number, and 1 special symbol.
2. **Session Fixation Prevention**: Sessions are regenerated upon every successful login challenge.
3. **Helmet Security Headers**: XSS filter, Content Security Policy (CSP), Frameguard (anti-clickjacking), and MIME type sniffing prevention.
4. **Rate Limiting**: Protects login and registration routes against distributed credential stuffing attacks.
