'use strict';

// ── State ────────────────────────────────────────────────────────────────────

let routingMode = 'all';
let authMethod = 'portal';
let lastConfig = '';
let lastZeroTrust = false;
let lastDeviceId = '';
let lastRegToken = '';

let otpState = null;
let authSession = null;
let tokenExpiresAt = 0;

const STORAGE_PORTAL_URL = 'warp_portal_url';

// ── DOM helpers ──────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

function show(el) {
  el.classList.remove('hidden');
}

function hide(el) {
  el.classList.add('hidden');
}

function setNote(el, message, kind) {
  if (!message) {
    hide(el);
    return;
  }
  el.textContent = message;
  el.className = `note ${kind || 'info'}`;
  show(el);
}

// ── Segmented controls ───────────────────────────────────────────────────────

function wireSegmentedControl(containerId, onSelect) {
  document.querySelectorAll(`#${containerId} button`).forEach((button) => {
    button.addEventListener('click', () => {
      document.querySelectorAll(`#${containerId} button`).forEach((b) => b.classList.remove('active'));
      button.classList.add('active');
      onSelect(button.dataset.mode || button.dataset.auth || button.dataset.epmode);
    });
  });
}

// ── Zero Trust panel ─────────────────────────────────────────────────────────

function updateZeroTrustUi() {
  const enabled = $('zero-trust-toggle').checked;
  $('zero-trust-panel').classList.toggle('hidden', !enabled);
  $('consumer-note').classList.toggle('hidden', enabled);
  updateNamePreview();
}

$('zero-trust-toggle').addEventListener('change', updateZeroTrustUi);

wireSegmentedControl('auth-method-seg', (method) => {
  authMethod = method;
  $('auth-portal').classList.toggle('hidden', method !== 'portal');
  $('auth-token').classList.toggle('hidden', method !== 'token');
});

const savedPortal = localStorage.getItem(STORAGE_PORTAL_URL);
if (savedPortal) $('portal-url').value = savedPortal;

$('portal-url').addEventListener('change', () => {
  localStorage.setItem(STORAGE_PORTAL_URL, $('portal-url').value.trim());
});

// ── Routing mode ─────────────────────────────────────────────────────────────

wireSegmentedControl('routing-mode-seg', (mode) => {
  routingMode = mode;
  $('mode-all').classList.toggle('hidden', mode !== 'all');
  $('mode-split').classList.toggle('hidden', mode !== 'split');
  $('v6-split-fields').classList.toggle('hidden', mode !== 'split' || !$('ipv6-toggle').checked);
  if (mode === 'split') updateCalcPreview();
});

$('ipv6-toggle').addEventListener('change', () => {
  const split = routingMode === 'split';
  $('v6-split-fields').classList.toggle('hidden', !split || !$('ipv6-toggle').checked);
  if (split) updateCalcPreview();
});

// ── Endpoint mode ────────────────────────────────────────────────────────────

wireSegmentedControl('endpoint-mode-seg', (mode) => {
  $('endpoint-default').classList.toggle('hidden', mode !== 'default');
  $('endpoint-ipv6').classList.toggle('hidden', mode !== 'ipv6');
  $('endpoint-nat64').classList.toggle('hidden', mode !== 'nat64');
});

const NAT64_PREFIXES = {
  CH: '2a14:7583:f764:64::',
  DE: '2001:67c:2960:6464::',
  NL: '2a02:898:146:64::',
  FI: '2001:67c:2b0:db32::',
  US1: '2602:fc59:11:64::',
  US2: '2602:fc59:b0:64::',
  HK: '2600:70ff:ac2c:64::',
};

function updateNat64Preview() {
  const prefix = NAT64_PREFIXES[$('nat64-country').value] || '';
  const raw = $('endpoint-nat64-ipv4').value.trim() || '162.159.192.7:2408';
  const [ipv4, port = '2408'] = raw.split(':');
  const valid = /^\d{1,3}(\.\d{1,3}){3}$/.test(ipv4 || '');
  $('nat64-preview-val').textContent = valid
    ? `[${prefix}${ipv4}]:${port}`
    : 'enter a valid IPv4 endpoint above';
}

$('nat64-country').addEventListener('change', updateNat64Preview);
$('endpoint-nat64-ipv4').addEventListener('input', updateNat64Preview);
updateNat64Preview();

// ── Obfuscation / SNI ────────────────────────────────────────────────────────

$('obfuscation-toggle').addEventListener('change', () => {
  $('sni-field').classList.toggle('hidden', !$('obfuscation-toggle').checked);
});

// ── Device name preview ──────────────────────────────────────────────────────

function emailPrefix() {
  const email = $('otp-email').value.trim();
  if (email.includes('@')) return email.split('@')[0];
  if (authMethod === 'token') {
    const token = $('token').value.trim();
    if (token.split('.').length === 3) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
        if (payload.email) return payload.email.split('@')[0];
      } catch {
        // ignore
      }
    }
  }
  return 'warp';
}

function updateNamePreview() {
  const host = $('device-name').value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  const prefix = emailPrefix();
  const stub = '‹xxxxx›';
  $('name-preview-val').textContent = host ? `${prefix}-${host}-${stub}` : `${prefix}-${stub}`;
}

$('device-name').addEventListener('input', updateNamePreview);
$('otp-email').addEventListener('input', updateNamePreview);
$('token').addEventListener('input', updateNamePreview);
updateNamePreview();

// ── AllowedIPs preview ───────────────────────────────────────────────────────

let calcTimer;

function parseList(value) {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function updateCalcPreview() {
  clearTimeout(calcTimer);
  calcTimer = setTimeout(async () => {
    const preview = $('calc-preview');
    const include = parseList($('include-custom').value);
    const exclude = parseList($('exclude-custom').value);

    if (!include.length) {
      preview.textContent = 'Enter at least one include subnet…';
      return;
    }

    const payload = { include, exclude, ipv6: $('ipv6-toggle').checked };
    if ($('ipv6-toggle').checked) {
      const v6Include = $('include-v6').value.trim();
      const v6Exclude = $('exclude-v6').value.trim();
      if (v6Include) payload.includeV6 = parseList(v6Include);
      if (v6Exclude) payload.excludeV6 = parseList(v6Exclude);
    }

    try {
      const response = await fetch('/api/calc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (data.error) {
        preview.innerHTML = `<span style="color:var(--red)">${data.error}</span>`;
        return;
      }
      preview.innerHTML = `<span class="count">${data.count} subnets →</span> ${data.allowedIps}`;
    } catch {
      preview.textContent = 'Preview unavailable';
    }
  }, 300);
}

['include-custom', 'exclude-custom', 'include-v6', 'exclude-v6'].forEach((id) => {
  $(id).addEventListener('input', updateCalcPreview);
});

// ── Token badge (Zero Trust) ─────────────────────────────────────────────────

function updateTokenBadge() {
  let badge = $('token-badge');
  if (!badge) {
    badge = document.createElement('span');
    badge.id = 'token-badge';
    const label = document.querySelector('#auth-token label');
    if (label) label.appendChild(badge);
  }

  const token = $('token').value.trim();
  if (!token) {
    badge.className = 'token-badge';
    badge.textContent = '';
    return;
  }

  const now = Date.now();
  if (tokenExpiresAt > now) {
    badge.className = 'token-badge fresh';
    badge.textContent = `✓ ${Math.round((tokenExpiresAt - now) / 1000)}s`;
  } else {
    badge.className = 'token-badge expired';
    badge.textContent = authSession ? '↻ auto-refresh' : '⚠ expired';
  }
}

setInterval(updateTokenBadge, 1000);

function setToken(token) {
  $('token').value = token;
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    tokenExpiresAt = (payload.exp || 0) * 1000;
  } catch {
    tokenExpiresAt = Date.now() + 55_000;
  }
  updateTokenBadge();
  updateNamePreview();
}

async function refreshToken() {
  if (!authSession) return false;
  try {
    const response = await fetch('/api/otp/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(authSession),
    });
    const data = await response.json();
    if (data.error) {
      authSession = null;
      return false;
    }
    setToken(data.token);
    return true;
  } catch {
    return false;
  }
}

// ── OTP flow ─────────────────────────────────────────────────────────────────

$('otp-send').addEventListener('click', async () => {
  const button = $('otp-send');
  const email = $('otp-email').value.trim();
  const portalUrl = $('portal-url').value.trim();

  if (!portalUrl) {
    setNote($('otp-status'), 'Enter your portal URL first.', 'warn');
    return;
  }
  if (!email) {
    setNote($('otp-status'), 'Enter your email first.', 'warn');
    return;
  }

  localStorage.setItem(STORAGE_PORTAL_URL, portalUrl);
  button.disabled = true;
  const label = button.textContent;
  button.innerHTML = '<span class="spinner"></span>Sending…';
  setNote($('otp-status'), '', null);

  try {
    const response = await fetch('/api/otp/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, portalUrl }),
    });
    const data = await response.json();
    if (data.error) {
      setNote($('otp-status'), data.error, 'warn');
      return;
    }

    otpState = data;
    show($('otp-code-row'));
    $('otp-code').focus();
    setNote($('otp-status'), 'Code sent — check your inbox (including spam). Valid for ~10 minutes.', 'info');
  } catch (error) {
    setNote($('otp-status'), `Network error: ${error.message}`, 'warn');
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
});

$('otp-verify').addEventListener('click', async () => {
  const button = $('otp-verify');
  const code = $('otp-code').value.trim();

  if (!otpState) {
    setNote($('otp-status'), 'Request a code first.', 'warn');
    return;
  }
  if (!/^\d{6}$/.test(code)) {
    setNote($('otp-status'), 'The code must be 6 digits.', 'warn');
    return;
  }

  button.disabled = true;
  const label = button.textContent;
  button.innerHTML = '<span class="spinner"></span>Verifying…';

  try {
    const response = await fetch('/api/otp/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, ...otpState }),
    });
    const data = await response.json();
    if (data.error) {
      setNote($('otp-status'), data.error, 'warn');
      return;
    }

    setToken(data.token);
    authSession = {
      authJar: data.authJar,
      portalHost: data.portalHost,
      portalOrigin: data.portalOrigin,
      appPath: data.appPath,
    };
    otpState = null;
    setNote($('otp-status'), 'Token received. Session saved — it will auto-refresh before generating.', 'ok');
  } catch (error) {
    setNote($('otp-status'), `Network error: ${error.message}`, 'warn');
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
});

// ── Generate config ──────────────────────────────────────────────────────────

function getRoutingPayload() {
  const ipv6 = $('ipv6-toggle').checked;
  if (routingMode === 'all') {
    return { include: ['0.0.0.0/0'], exclude: [], ipv6 };
  }

  const include = parseList($('include-custom').value);
  const exclude = parseList($('exclude-custom').value);
  const payload = { include, exclude, ipv6 };

  if (ipv6) {
    payload.includeV6 = parseList($('include-v6').value || '::/0');
    payload.excludeV6 = parseList($('exclude-v6').value);
  }

  return payload;
}

$('gen').addEventListener('click', async () => {
  const button = $('gen');
  const errorBox = $('err');
  const result = $('result');

  errorBox.classList.remove('show');
  result.classList.remove('show');

  const zeroTrust = $('zero-trust-toggle').checked;
  let token = '';

  if (zeroTrust) {
    token = $('token').value.trim();
    if (!token) {
      errorBox.textContent = authMethod === 'portal'
        ? 'Complete the email OTP flow or switch to JWT token mode.'
        : 'Enter a JWT token.';
      errorBox.classList.add('show');
      return;
    }

    if (tokenExpiresAt <= Date.now() && authSession) {
      button.disabled = true;
      button.innerHTML = '<span class="spinner"></span>Refreshing token…';
      const ok = await refreshToken();
      if (!ok) {
        errorBox.textContent = 'Session expired — please authenticate again.';
        errorBox.classList.add('show');
        button.disabled = false;
        button.textContent = 'Generate config';
        return;
      }
      token = $('token').value.trim();
    }
  }

  const routing = getRoutingPayload();
  if (routingMode === 'split' && !routing.include.length) {
    errorBox.textContent = 'Enter at least one include subnet for split tunnel mode.';
    errorBox.classList.add('show');
    return;
  }

  button.disabled = true;
  button.innerHTML = '<span class="spinner"></span>Registering device…';

  try {
    const endpointMode = document.querySelector('#endpoint-mode-seg button.active').dataset.epmode;
    const endpointValue =
      endpointMode === 'nat64'
        ? $('endpoint-nat64-ipv4').value.trim()
        : $('endpoint').value.trim();

    const response = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        zeroTrust,
        token,
        dns: $('dns').value.trim(),
        ...routing,
        sni: $('sni').value.trim(),
        endpoint: endpointValue,
        endpointMode,
        nat64Country: $('nat64-country').value,
        obfuscation: $('obfuscation-toggle').checked,
        deviceName: $('device-name').value.trim(),
      }),
    });

    const data = await response.json();
    if (data.error) {
      errorBox.textContent = data.error;
      errorBox.classList.add('show');
      return;
    }

    lastConfig = data.config;
    lastZeroTrust = zeroTrust;
    lastDeviceId = data.deviceId || '';
    lastRegToken = data.regToken || '';

    $('config-out').textContent = data.config;
    if (data.deviceName) $('name-preview-val').textContent = data.deviceName;

    hide($('qrwrap'));
    $('qrcode').innerHTML = '';
    $('qrbtn').textContent = 'Show QR';
    $('revoke-status').textContent = '';
    show($('revoke-btn'));

    result.classList.add('show');
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    errorBox.textContent = `Network error: ${error.message}`;
    errorBox.classList.add('show');
  } finally {
    button.disabled = false;
    button.textContent = 'Generate config';
  }
});

// ── Result actions ───────────────────────────────────────────────────────────

$('copy').addEventListener('click', (event) => {
  navigator.clipboard.writeText(lastConfig).then(() => {
    event.target.textContent = 'Copied!';
    event.target.classList.add('copied');
    setTimeout(() => {
      event.target.textContent = 'Copy';
      event.target.classList.remove('copied');
    }, 1800);
  });
});

$('download').addEventListener('click', () => {
  const blob = new Blob([lastConfig], { type: 'text/plain' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'warp-amnezia.conf';
  link.click();
  URL.revokeObjectURL(link.href);
});

$('qrbtn').addEventListener('click', () => {
  const wrap = $('qrwrap');
  const box = $('qrcode');
  const button = $('qrbtn');

  if (!wrap.classList.contains('hidden')) {
    hide(wrap);
    button.textContent = 'Show QR';
    return;
  }

  box.innerHTML = '';
  const qrConfig = lastConfig
    .split('\n')
    .filter((line) => !line.trim().startsWith('#'))
    .join('\n')
    .replace(/\n\n+/g, '\n\n');

  try {
    if (qrConfig.length > 2953) throw new Error('too large');
    new QRCode(box, {
      text: qrConfig,
      width: 320,
      height: 320,
      correctLevel: QRCode.CorrectLevel.L,
    });
    $('qrnote').classList.toggle('hidden', qrConfig.length <= 1500);
    show(wrap);
    button.textContent = 'Hide QR';
  } catch {
    show($('qrnote'));
    show(wrap);
    button.textContent = 'Hide QR';
  }
});

$('deeplink').addEventListener('click', (event) => {
  const stripped = lastConfig
    .split('\n')
    .filter((line) => !line.trim().startsWith('#'))
    .join('\n')
    .replace(/\n\n+/g, '\n\n');
  const uri = `awg://import/${btoa(unescape(encodeURIComponent(stripped)))}`;

  navigator.clipboard.writeText(uri).then(() => {
    event.target.textContent = 'Copied!';
    event.target.classList.add('copied');
    setTimeout(() => {
      event.target.textContent = 'Deep link';
      event.target.classList.remove('copied');
    }, 1800);
  }).catch(() => window.open(uri, '_blank'));
});

$('revoke-btn').addEventListener('click', async () => {
  const button = $('revoke-btn');
  const status = $('revoke-status');

  const idMatch = lastConfig.match(/#CFDeviceId\s*=\s*(\S+)/);
  const tokenMatch = lastConfig.match(/#CFToken\s*=\s*(\S+)/);
  const refreshMatch = lastConfig.match(/^#\s*([^,]+),([^,]+),/m);

  const deviceId = lastDeviceId || (idMatch ? idMatch[1] : refreshMatch ? refreshMatch[2] : null);
  const regToken = lastRegToken || (tokenMatch ? tokenMatch[1] : refreshMatch ? refreshMatch[1] : null);

  if (!deviceId || !regToken) {
    status.textContent = 'Cannot find device credentials in config.';
    return;
  }

  if (!confirm('Revoke this device? The config will stop working.')) return;

  button.disabled = true;
  status.textContent = 'Revoking…';

  try {
    const response = await fetch('/api/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId, regToken, zeroTrust: lastZeroTrust }),
    });
    const data = await response.json();
    if (data.error) {
      status.textContent = `✗ ${data.error}`;
      status.style.color = '#fca5a5';
    } else {
      status.textContent = '✓ Device revoked.';
      status.style.color = '#86efac';
      hide(button);
    }
  } catch (error) {
    status.textContent = `Error: ${error.message}`;
  } finally {
    button.disabled = false;
  }
});

// ── Init ─────────────────────────────────────────────────────────────────────

updateZeroTrustUi();
