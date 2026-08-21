// Dashboard UI Logic

document.addEventListener('DOMContentLoaded', () => {
  let currentUser = null;

  // Elements
  const navUsername = document.getElementById('navUsername');
  const profUsername = document.getElementById('profUsername');
  const profEmail = document.getElementById('profEmail');
  const profId = document.getElementById('profId');
  const profCreated = document.getElementById('profCreated');
  const profLastLogin = document.getElementById('profLastLogin');
  const logoutBtn = document.getElementById('logoutBtn');
  const twoFactorStatusBadge = document.getElementById('twoFactorStatusBadge');
  const toggle2FABtn = document.getElementById('toggle2FABtn');
  const logsContainer = document.getElementById('logsContainer');
  const refreshLogsBtn = document.getElementById('refreshLogsBtn');
  const dashAlert = document.getElementById('dashAlert');
  const dashAlertMsg = document.getElementById('dashAlertMsg');
  const dashAlertIcon = document.getElementById('dashAlertIcon');

  // Modals
  const modal2FASetup = document.getElementById('modal2FASetup');
  const close2FAModal = document.getElementById('close2FAModal');
  const cancel2FASetupBtn = document.getElementById('cancel2FASetupBtn');
  const qrCodeImg = document.getElementById('qrCodeImg');
  const secretKeyText = document.getElementById('secretKeyText');
  const verify2FASetupForm = document.getElementById('verify2FASetupForm');
  const setupToken = document.getElementById('setupToken');

  const modal2FADisable = document.getElementById('modal2FADisable');
  const close2FADisableModal = document.getElementById('close2FADisableModal');
  const cancelDisable2FABtn = document.getElementById('cancelDisable2FABtn');
  const disable2FAForm = document.getElementById('disable2FAForm');
  const disable2FAPassword = document.getElementById('disable2FAPassword');

  // Password Change
  const changePasswordForm = document.getElementById('changePasswordForm');

  // Notification helper
  function showDashAlert(message, type = 'success') {
    dashAlert.classList.remove('hidden', 'bg-emerald-950/70', 'border-emerald-800/80', 'text-emerald-200', 'bg-rose-950/70', 'border-rose-800/80', 'text-rose-200');
    
    if (type === 'success') {
      dashAlert.classList.add('bg-emerald-950/70', 'border', 'border-emerald-800/80', 'text-emerald-200');
      dashAlertIcon.className = 'fa-solid fa-circle-check mt-0.5 text-emerald-400';
    } else {
      dashAlert.classList.add('bg-rose-950/70', 'border', 'border-rose-800/80', 'text-rose-200');
      dashAlertIcon.className = 'fa-solid fa-circle-exclamation mt-0.5 text-rose-400';
    }

    dashAlertMsg.textContent = message;
    dashAlert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    setTimeout(() => {
      dashAlert.classList.add('hidden');
    }, 6000);
  }

  // Format dates
  function formatDate(dateStr) {
    if (!dateStr) return 'First session';
    const date = new Date(dateStr);
    return date.toLocaleString();
  }

  // Load User Profile
  async function loadUserProfile() {
    try {
      const res = await fetch('/api/auth/me');
      const data = await res.json();

      if (!res.ok || !data.success) {
        window.location.href = '/';
        return;
      }

      currentUser = data.user;
      renderProfile(currentUser);
      loadLogs();
    } catch (err) {
      window.location.href = '/';
    }
  }

  // Render Profile & 2FA State
  function renderProfile(user) {
    navUsername.textContent = user.username;
    profUsername.textContent = user.username;
    profEmail.textContent = user.email;
    profId.textContent = `#${user.id}`;
    profCreated.textContent = formatDate(user.createdAt);
    profLastLogin.textContent = formatDate(user.lastLogin);

    if (user.twoFactorEnabled) {
      twoFactorStatusBadge.className = 'inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-950/80 border border-emerald-700/80 text-emerald-300';
      twoFactorStatusBadge.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span><span>Active (Protected)</span>';

      toggle2FABtn.className = 'px-4 py-2 rounded-xl text-xs font-medium bg-rose-600/20 hover:bg-rose-600/30 border border-rose-500/40 text-rose-300 transition duration-200';
      toggle2FABtn.innerHTML = '<i class="fa-solid fa-shield-xmark mr-1.5"></i>Disable 2FA';
      toggle2FABtn.onclick = openDisableModal;
    } else {
      twoFactorStatusBadge.className = 'inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-950/80 border border-amber-700/80 text-amber-300';
      twoFactorStatusBadge.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span><span>Disabled</span>';

      toggle2FABtn.className = 'px-4 py-2 rounded-xl text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/30 transition duration-200';
      toggle2FABtn.innerHTML = '<i class="fa-solid fa-shield-check mr-1.5"></i>Enable 2FA';
      toggle2FABtn.onclick = openSetupModal;
    }
  }

  // Load Audit Logs
  async function loadLogs() {
    try {
      const res = await fetch('/api/user/logs');
      const data = await res.json();

      if (res.ok && data.success && data.logs) {
        if (data.logs.length === 0) {
          logsContainer.innerHTML = '<div class="text-center text-slate-500 py-6">No audit records found.</div>';
          return;
        }

        logsContainer.innerHTML = data.logs.map(log => {
          let badgeClass = 'bg-slate-800 text-slate-300';
          let icon = 'fa-circle-info';

          if (log.event_type.includes('SUCCESS') || log.event_type.includes('REGISTERED') || log.event_type.includes('ENABLED')) {
            badgeClass = 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/60';
            icon = 'fa-circle-check';
          } else if (log.event_type.includes('FAILED')) {
            badgeClass = 'bg-rose-950/70 text-rose-400 border border-rose-800/60';
            icon = 'fa-triangle-exclamation';
          } else if (log.event_type.includes('2FA') || log.event_type.includes('PASSWORD')) {
            badgeClass = 'bg-indigo-950/70 text-indigo-300 border border-indigo-800/60';
            icon = 'fa-shield-halved';
          }

          return `
            <div class="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition">
              <div class="flex items-center justify-between mb-1">
                <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${badgeClass}">
                  <i class="fa-solid ${icon} mr-1 text-[9px]"></i>${log.event_type}
                </span>
                <span class="text-[10px] text-slate-500">${new Date(log.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
              </div>
              <p class="text-slate-300 text-xs mb-1">${log.details || 'Security event recorded'}</p>
              <div class="text-[10px] text-slate-500 flex items-center justify-between">
                <span>IP: ${log.ip_address}</span>
                <span>${new Date(log.created_at).toLocaleDateString()}</span>
              </div>
            </div>
          `;
        }).join('');
      }
    } catch (err) {
      logsContainer.innerHTML = '<div class="text-center text-rose-400 py-6">Failed to load audit logs.</div>';
    }
  }

  refreshLogsBtn.addEventListener('click', loadLogs);

  // 2FA Setup Flow
  async function openSetupModal() {
    try {
      const res = await fetch('/api/auth/2fa/generate', { method: 'POST' });
      const data = await res.json();

      if (res.ok && data.success) {
        qrCodeImg.src = data.qrCodeDataUrl;
        secretKeyText.textContent = data.secret;
        setupToken.value = '';
        modal2FASetup.classList.remove('hidden');
        setupToken.focus();
      } else {
        showDashAlert(data.message || 'Failed to initialize 2FA setup.', 'error');
      }
    } catch (err) {
      showDashAlert('Error connecting to server for 2FA setup.', 'error');
    }
  }

  close2FAModal.addEventListener('click', () => modal2FASetup.classList.add('hidden'));
  cancel2FASetupBtn.addEventListener('click', () => modal2FASetup.classList.add('hidden'));

  verify2FASetupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const token = setupToken.value.trim();
    if (!token || token.length !== 6) return;

    try {
      const res = await fetch('/api/auth/2fa/enable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      const data = await res.json();

      if (res.ok && data.success) {
        modal2FASetup.classList.add('hidden');
        showDashAlert('Two-Factor Authentication is now enabled for your account!', 'success');
        loadUserProfile();
      } else {
        alert(data.message || 'Invalid code. Please try again.');
      }
    } catch (err) {
      alert('Verification request failed.');
    }
  });

  // 2FA Disable Flow
  function openDisableModal() {
    disable2FAPassword.value = '';
    modal2FADisable.classList.remove('hidden');
    disable2FAPassword.focus();
  }

  close2FADisableModal.addEventListener('click', () => modal2FADisable.classList.add('hidden'));
  cancelDisable2FABtn.addEventListener('click', () => modal2FADisable.classList.add('hidden'));

  disable2FAForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = disable2FAPassword.value;

    try {
      const res = await fetch('/api/auth/2fa/disable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });

      const data = await res.json();

      if (res.ok && data.success) {
        modal2FADisable.classList.add('hidden');
        showDashAlert('Two-Factor Authentication has been disabled.', 'success');
        loadUserProfile();
      } else {
        alert(data.message || 'Failed to disable 2FA.');
      }
    } catch (err) {
      alert('Server error while disabling 2FA.');
    }
  });

  // Handle Password Change
  changePasswordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmNewPassword = document.getElementById('confirmNewPassword').value;

    if (newPassword !== confirmNewPassword) {
      showDashAlert('New passwords do not match.', 'error');
      return;
    }

    try {
      const res = await fetch('/api/user/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword })
      });

      const data = await res.json();

      if (res.ok && data.success) {
        showDashAlert('Password changed successfully!', 'success');
        changePasswordForm.reset();
        loadLogs();
      } else {
        showDashAlert(data.message || 'Could not change password.', 'error');
      }
    } catch (err) {
      showDashAlert('Network error occurred.', 'error');
    }
  });

  // Handle Logout
  logoutBtn.addEventListener('click', async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (err) {
    } finally {
      window.location.href = '/';
    }
  });

  // Init
  loadUserProfile();
});
