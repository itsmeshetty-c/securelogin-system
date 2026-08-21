const express = require('express');
const User = require('../models/User');
const { requireAuth } = require('../middleware/authMiddleware');

const router = express.Router();

router.get('/dashboard', requireAuth, (req, res) => {
  try {
    const user = User.findById(req.session.userId);

    if (!user) {
      req.session.destroy();
      return res.redirect('/login');
    }

    res.render('dashboard', {
      title: 'User Dashboard',
      user
    });
  } catch (err) {
    console.error('[DASHBOARD ERROR]:', err);
    req.flash('error', 'Unable to load dashboard.');
    return res.redirect('/login');
  }
});

module.exports = router;
