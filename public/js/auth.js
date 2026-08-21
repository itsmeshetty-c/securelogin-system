// Auth page logic (Login, Registration, 2FA Challenge, Password Strength Meter)

document.addEventListener('DOMContentLoaded', () => {
  const tabLoginBtn = document.getElementById('tabLoginBtn');
  const tabRegisterBtn = document.getElementById('tabRegisterBtn');
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  const twoFactorForm = document.getElementById('twoFactorForm');
  const authTabs = document.getElementById('authTabs');
  const alertBox = document.getElementById('alertBox');
  const alertMsg = document.getElementById('alertMsg');
  const alertIcon = document.getElementById('alertIcon');
  const cancel2FABtn = document.getElementById('cancel2FABtn');

  // Password fields
  const regPassword = document.getElementById('regPassword');
  const strengthBar = document.getElementById('strengthBar');
  const strengthLabel = document.getElementById('strengthLabel');
  const strengthAdvice = document.getElementById('strengthAdvice');

  // Password visibility toggle buttons
  document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = btn.parentElement.querySelector('input');
      const icon = btn.querySelector('i');
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    });
  });

  // Tab switching
  function switchTab(tab) {
    hideAlert();
    if (tab === 'login') {
      tabLoginBtn.className = 'flex-1 pb-3 text-center font-medium text-sm text-indigo-400 border-b-2 border-indigo-500 transition duration-200';
      tabRegisterBtn.className = 'flex-1 pb-3 text-center font-medium text-sm text-slate-400 hover:text-slate-200 border-b-2 border-transparent transition duration-200';
      loginForm.classList.remove('hidden');
      registerForm.classList.add('hidden');
      twoFactorForm.classList.add('hidden');
      authTabs.classList.remove('hidden');
    } else if (tab === 'register') {
      tabRegisterBtn.className = 'flex-1 pb-3 text-center font-medium text-sm text-emerald-400 border-b-2 border-emerald-500 transition duration-200';
      tabLoginBtn.className = 'flex-1 pb-3 text-center font-medium text-sm text-slate-400 hover:text-slate-200 border-b-2 border-transparent transition duration-200';
      registerForm.classList.remove('hidden');
      loginForm.classList.add('hidden');
      twoFactorForm.classList.add('hidden');
      authTabs.classList.remove('hidden');
    } else if (tab === '2fa') {
      loginForm.classList.add('hidden');
      registerForm.classList.add('hidden');
      authTabs.classList.add('hidden');
      twoFactorForm.classList.remove('hidden');
      document.getElementById('twoFactorToken').value = '';
      document.getElementById('twoFactorToken').focus();
    }
  }

  tabLoginBtn.addEventListener('click', () => switchTab('login'));
  tabRegisterBtn.addEventListener('click', () => switchTab('register'));
  cancel2FABtn.addEventListener('click', () => switchTab('login'));

  // Alert box helpers
  function showAlert(message, type = 'error') {
    alertBox.classList.remove('hidden', 'bg-rose-950/70', 'border-rose-800/80', 'text-rose-200', 'bg-emerald-950/70', 'border-emerald-800/80', 'text-emerald-200', 'bg-amber-950/70', 'border-amber-800/80', 'text-amber-200');
    
    if (type === 'error') {
      alertBox.classList.add('bg-rose-950/70', 'border', 'border-rose-800/80', 'text-rose-200');
      alertIcon.className = 'fa-solid fa-circle-exclamation mt-0.5 text-rose-400';
    } else if (type === 'success') {
      alertBox.classList.add('bg-emerald-950/70', 'border', 'border-emerald-800/80', 'text-emerald-200');
      alertIcon.className = 'fa-solid fa-circle-check mt-0.5 text-emerald-400';
    } else if (type === 'info') {
      alertBox.classList.add('bg-amber-950/70', 'border', 'border-amber-800/80', 'text-amber-200');
      alertIcon.className = 'fa-solid fa-triangle-exclamation mt-0.5 text-amber-400';
    }
    
    alertMsg.textContent = message;
  }

  function hideAlert() {
    alertBox.classList.add('hidden');
  }

  // Live password strength calculation
  if (regPassword) {
    regPassword.addEventListener('input', () => {
      const val = regPassword.value;
      let score = 0;
      let advice = [];

      if (val.length >= 8) score += 1;
      else advice.push('8+ chars');

      if (/[A-Z]/.test(val)) score += 1;
      else advice.push('uppercase');

      if (/[a-z]/.test(val)) score += 1;
      else advice.push('lowercase');

      if (/[0-9]/.test(val)) score += 1;
      else advice.push('number');

      if (/[^A-Za-z0-9]/.test(val)) score += 1;
      else advice.push('symbol');

      if (val.length === 0) {
        strengthBar.style.width = '0%';
        strengthBar.className = 'strength-bar w-0 bg-slate-700';
        strengthLabel.textContent = 'Too Short';
        strengthLabel.className = 'text-slate-400';
        strengthAdvice.textContent = '8+ chars required';
        return;
      }

      if (score <= 2) {
        strengthBar.style.width = '25%';
        strengthBar.className = 'strength-bar bg-rose-500';
        strengthLabel.textContent = 'Weak';
        strengthLabel.className = 'text-rose-400 font-semibold';
      } else if (score === 3 || score === 4) {
        strengthBar.style.width = '65%';
        strengthBar.className = 'strength-bar bg-amber-500';
        strengthLabel.textContent = 'Medium';
        strengthLabel.className = 'text-amber-400 font-semibold';
      } else if (score === 5) {
        strengthBar.style.width = '100%';
        strengthBar.className = 'strength-bar bg-emerald-500';
        strengthLabel.textContent = 'Strong';
        strengthLabel.className = 'text-emerald-400 font-semibold';
      }

      strengthAdvice.textContent = advice.length > 0 ? `Need: ${advice.slice(0, 2).join(', ')}` : 'Secure password!';
    });
  }

  // Handle Login Submit
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const identifier = document.getElementById('loginIdentifier').value.trim();
    const password = document.getElementById('loginPassword').value;
    const submitBtn = document.getElementById('loginSubmitBtn');

    if (!identifier || !password) {
      showAlert('Please enter both username/email and password.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Verifying...</span>';

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier, password })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        if (data.requires2FA) {
          showAlert(data.message, 'info');
          switchTab('2fa');
        } else {
          showAlert('Login successful! Redirecting...', 'success');
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 600);
        }
      } else {
        showAlert(data.message || 'Login failed.');
      }
    } catch (err) {
      showAlert('Unable to connect to server. Please try again.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Sign In</span><i class="fa-solid fa-arrow-right text-xs"></i>';
    }
  });

  // Handle 2FA Challenge Submit
  twoFactorForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const token = document.getElementById('twoFactorToken').value.trim();
    const submitBtn = document.getElementById('twoFactorSubmitBtn');

    if (!token || token.length !== 6) {
      showAlert('Please enter a 6-digit code.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Verifying Token...</span>';

    try {
      const response = await fetch('/api/auth/verify-2fa-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        showAlert('2FA Verified! Redirecting...', 'success');
        setTimeout(() => {
          window.location.href = '/dashboard';
        }, 600);
      } else {
        showAlert(data.message || 'Invalid 2FA code.');
      }
    } catch (err) {
      showAlert('Verification request failed. Please try again.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Verify & Complete Login</span><i class="fa-solid fa-arrow-right text-xs"></i>';
    }
  });

  // Handle Registration Submit
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const username = document.getElementById('regUsername').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const password = document.getElementById('regPassword').value;
    const confirmPassword = document.getElementById('regConfirmPassword').value;
    const submitBtn = document.getElementById('regSubmitBtn');

    if (password !== confirmPassword) {
      showAlert('Passwords do not match.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Securing & Registering...</span>';

    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        showAlert(data.message, 'success');
        registerForm.reset();
        setTimeout(() => {
          switchTab('login');
          document.getElementById('loginIdentifier').value = username;
          showAlert('Account created! Please sign in with your credentials.', 'success');
        }, 1200);
      } else {
        showAlert(data.message || 'Registration failed.');
      }
    } catch (err) {
      showAlert('Server error during registration. Please try again.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Create Account</span><i class="fa-solid fa-check text-xs"></i>';
    }
  });

  // Auto-check if already logged in
  fetch('/api/auth/me')
    .then(res => res.json())
    .then(data => {
      if (data.success && data.user) {
        window.location.href = '/dashboard';
      }
    })
    .catch(() => {});
});
