const API_KEYS = {
  claude:         { label: 'Claude AI',      storageKey: 'pc_key_claude'         },
  virustotal:     { label: 'VirusTotal',     storageKey: 'pc_key_virustotal'     },
  shodan:         { label: 'Shodan',         storageKey: 'pc_key_shodan'         },
  hibp:           { label: 'HIBP',           storageKey: 'pc_key_hibp'           },
  securitytrails: { label: 'SecurityTrails', storageKey: 'pc_key_securitytrails' },
  github:         { label: 'GitHub',         storageKey: 'pc_key_github'         },
};

const MODE_DESCRIPTIONS = {
  explorer: 'Explorer mode explains findings in plain English with zero jargon. Ideal for business owners, individuals and non-technical users.',
  analyst:  'Analyst mode produces a structured professional security report. Business risk focused with industry terminology briefly explained.',
  operator: 'Operator mode outputs raw technical intelligence. CVE references, full JSON available, terminal aesthetic. No hand-holding.',
};

let currentMode = 'explorer';

document.addEventListener('DOMContentLoaded', function() {
  cacheCleanExpired();
  renderApiStatusBar();
  loadSavedKeys();
  updateScansRemaining();
  loadSavedMode();
  
  (function() {
    const params = new URLSearchParams(window.location.search);
    const t = params.get('t');
    const m = params.get('m');
    if (!t) return;
    const input = document.getElementById('searchInput');
    if (input) input.value = t;
    if (m && ['explorer', 'analyst', 'operator'].includes(m)) {
      suggestMode(m);
    }
    handleInputChange(t);
    if (localStorage.getItem('pc_terms')) {
      setTimeout(function() { runScan(t, detectInputType(t), currentMode); }, 400);
    }
  })();
  
  if (!localStorage.getItem('pc_terms')) {
    document.getElementById('termsNotice').classList.remove('hidden');
  }

  document.querySelectorAll('.mode-tab').forEach(function(tab) {
    tab.addEventListener('click', function() {
      document.querySelectorAll('.mode-tab').forEach(function(t) {
        t.classList.remove('active');
      });
      tab.classList.add('active');
      currentMode = tab.dataset.mode;
      saveMode(currentMode);
      document.getElementById('modeContextText').textContent =
        MODE_DESCRIPTIONS[currentMode];
    });
  });

  document.getElementById('settingsBtn').addEventListener('click', function(e) {
    e.preventDefault();
    openSettings();
  });

  document.getElementById('apiStatusSetupBtn').addEventListener('click', openSettings);
  document.getElementById('settingsClose').addEventListener('click', closeSettings);

  document.getElementById('settingsOverlay').addEventListener('click', function(e) {
    if (e.target === document.getElementById('settingsOverlay')) closeSettings();
  });

  document.getElementById('saveKeysBtn').addEventListener('click', saveKeys);

  document.getElementById('searchInput').addEventListener('input', function() {
    handleInputChange(this.value);
  });

  document.getElementById('scanBtn').addEventListener('click', function() {
    initiateScan();
  });
  
  document.getElementById('exportPdfBtn').addEventListener('click', exportPdf);
  document.getElementById('copyReportBtn').addEventListener('click', copyReport);
  document.getElementById('shareReportBtn').addEventListener('click', shareReport);
  
  document.getElementById('searchInput').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') initiateScan();
  });

  document.addEventListener('click', function(e) {
    const header = e.target.closest('.api-card-header');
    if (!header) return;
    header.closest('.api-card').classList.toggle('expanded');
  });
});

function handleInputChange(val) {
  const type = detectInputType(val);
  const badge = document.getElementById('inputTypeBadge');
  const hint  = document.getElementById('inputHint');

  badge.textContent = BADGE_LABELS[type];

  if (type !== INPUT_TYPES.UNKNOWN && val.trim()) {
    const suggested = MODE_SUGGESTIONS[type];
    suggestMode(suggested);
    hint.textContent = 'Detected: ' + type.toLowerCase() +
      ' — ' + suggested + ' mode suggested';
  } else {
    hint.textContent = 'Supports: domains · email addresses · IP addresses';
  }
}

function suggestMode(mode) {
  document.querySelectorAll('.mode-tab').forEach(function(tab) {
    tab.classList.remove('active');
    if (tab.dataset.mode === mode) tab.classList.add('active');
  });
  currentMode = mode;
  document.getElementById('modeContextText').textContent =
    MODE_DESCRIPTIONS[mode];
}

function initiateScan() {
  const input = document.getElementById('searchInput');
  const val   = input.value.trim();

  const terms = localStorage.getItem('pc_terms');
  const checkbox = document.getElementById('termsCheckbox');
  const termsNotice = document.getElementById('termsNotice');

  if (!terms) {
    if (!checkbox || !checkbox.checked) {
      flashBorder(termsNotice, 'var(--critical)');
      return;
    }
    localStorage.setItem('pc_terms', 'true');
    termsNotice.classList.add('hidden');
  }

  const validation = validateInput(val);
  if (!validation.ok) {
    flashBorder(input, 'var(--critical)');
    document.getElementById('inputHint').textContent = validation.msg;
    document.getElementById('inputHint').style.color = 'var(--critical)';
    setTimeout(function() {
      document.getElementById('inputHint').style.color = '';
      document.getElementById('inputHint').textContent =
        'Supports: domains · email addresses · IP addresses';
    }, 3000);
    return;
  }

  if (!checkRateLimit()) {
    document.getElementById('inputHint').textContent =
      'Daily limit reached (5 scans). Resets at midnight.';
    document.getElementById('inputHint').style.color = 'var(--warning)';
    return;
  }

  incrementRateLimit();
  updateScansRemaining();

  // Hands off to scanner — built in Module 4
  runScan(val, validation.type, currentMode);
}

function updateScansRemaining() {
  const el = document.getElementById('searchesRemaining');
  if (el) el.textContent = scansRemaining() + ' scans remaining today';
}

function openSettings() {
  document.getElementById('settingsOverlay').classList.remove('hidden');
}

function closeSettings() {
  document.getElementById('settingsOverlay').classList.add('hidden');
}

function forceFreshScan() {
  const input = document.getElementById('searchInput');
  const val = input ? input.value.trim() : '';
  if (!val) return;
  const validation = validateInput(val);
  if (!validation.ok) return;
  cacheClear();
  runScan(val, validation.type, currentMode);
}

function saveKeys() {
  let saved = 0;
  Object.entries(API_KEYS).forEach(function([id, cfg]) {
    const input = document.getElementById('key-' + id);
    if (!input) return;
    const val = input.value.trim();
    if (val) {
      localStorage.setItem(cfg.storageKey, val);
      saved++;
      const ind = document.getElementById('indicator-' + id);
      if (ind) ind.classList.add('active');
      const field = document.getElementById('byok-' + id);
      if (field) field.classList.add('has-key');
    } else {
      localStorage.removeItem(cfg.storageKey);
      const ind = document.getElementById('indicator-' + id);
      if (ind) ind.classList.remove('active');
      const field = document.getElementById('byok-' + id);
      if (field) field.classList.remove('has-key');
    }
  });

  renderApiStatusBar();

  const btn = document.getElementById('saveKeysBtn');
  const orig = btn.textContent;
  btn.textContent = saved > 0 ? '✓ ' + saved + ' KEY(S) SAVED' : '✓ KEYS CLEARED';
  setTimeout(function() { btn.textContent = orig; }, 2000);
  setTimeout(closeSettings, 800);
}

function loadSavedKeys() {
  Object.entries(API_KEYS).forEach(function([id, cfg]) {
    const saved = localStorage.getItem(cfg.storageKey);
    const input = document.getElementById('key-' + id);
    if (!input) return;
    if (saved) {
      input.value = saved;
      const ind = document.getElementById('indicator-' + id);
      if (ind) ind.classList.add('active');
      const field = document.getElementById('byok-' + id);
      if (field) field.classList.add('has-key');
    }
  });
}

function renderApiStatusBar() {
  const container = document.getElementById('apiStatusPills');
  if (!container) return;
  container.innerHTML = '';

  ['crt.sh', 'urlscan.io', 'AbuseIPDB', 'DNS', 'Africa Check'].forEach(function(name) {
    container.appendChild(makePill(name, true));
  });

  Object.entries(API_KEYS).forEach(function([id, cfg]) {
    container.appendChild(makePill(cfg.label, !!localStorage.getItem(cfg.storageKey)));
  });
}

function makePill(label, ready) {
  const pill = document.createElement('div');
  pill.className = 'status-pill ' + (ready ? 'ready' : 'missing');
  const dot = document.createElement('span');
  dot.className = 'status-pill-dot';
  const text = document.createElement('span');
  text.textContent = label;
  pill.appendChild(dot);
  pill.appendChild(text);
  return pill;
}

function flashBorder(el, color) {
  el.style.borderColor = color;
  setTimeout(function() { el.style.borderColor = ''; }, 1500);
}
const KEY_VALIDATORS = {
  claude:         function(k) { return k.startsWith('sk-ant-'); },
  virustotal:     function(k) { return k.length === 64; },
  shodan:         function(k) { return k.length >= 32; },
  hibp:           function(k) { return k.length >= 32; },
  securitytrails: function(k) { return k.length >= 20; },
  github:         function(k) { return k.startsWith('ghp_') || k.startsWith('github_pat_'); },
};

const KEY_TESTS = {
  claude: async function(k) {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': k,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 10,
        messages: [{ role: 'user', content: 'hi' }]
      }),
      signal: AbortSignal.timeout(10000)
    });
    return res.ok;
  },

  virustotal: async function(k) {
    const res = await fetch(
      'https://www.virustotal.com/api/v3/domains/example.com',
      {
        headers: { 'x-apikey': k },
        signal: AbortSignal.timeout(10000)
      }
    );
    return res.ok;
  },

  shodan: async function(k) {
    const res = await fetch(
      'https://api.shodan.io/api-info?key=' + encodeURIComponent(k),
      { signal: AbortSignal.timeout(10000) }
    );
    return res.ok;
  },

  hibp: async function(k) {
    const res = await fetch(
      'https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com',
      {
        headers: { 'hibp-api-key': k, 'User-Agent': 'PhantomCheck-OSINT' },
        signal: AbortSignal.timeout(10000)
      }
    );
    return res.ok || res.status === 404;
  },

  securitytrails: async function(k) {
    const res = await fetch(
      'https://api.securitytrails.com/v1/domain/example.com',
      {
        headers: { 'APIKEY': k },
        signal: AbortSignal.timeout(10000)
      }
    );
    return res.ok;
  },

  github: async function(k) {
    const res = await fetch('https://api.github.com/rate_limit', {
      headers: { 'Authorization': 'token ' + k },
      signal: AbortSignal.timeout(10000)
    });
    return res.ok;
  }
};

async function testKey(id) {
  const input = document.getElementById('key-' + id);
  const resultEl = document.getElementById('test-result-' + id);
  const btn = document.getElementById('test-' + id);

  if (!input || !resultEl || !btn) return;

  const val = input.value.trim();

  if (!val) {
    resultEl.textContent = 'Enter a key first';
    resultEl.style.color = 'var(--warning)';
    return;
  }

  const validator = KEY_VALIDATORS[id];
  if (validator && !validator(val)) {
    resultEl.textContent = 'Key format looks wrong';
    resultEl.style.color = 'var(--critical)';
    return;
  }

  btn.textContent = 'Testing...';
  btn.disabled = true;
  resultEl.textContent = '';

  try {
    const tester = KEY_TESTS[id];
    if (!tester) {
      resultEl.textContent = 'No test available';
      resultEl.style.color = 'var(--text-muted)';
      return;
    }

    const ok = await tester(val);
    resultEl.textContent = ok ? '✓ Key works' : '✗ Key rejected by API';
    resultEl.style.color = ok ? 'var(--safe)' : 'var(--critical)';

    if (ok) {
      localStorage.setItem(API_KEYS[id].storageKey, val);
      const ind = document.getElementById('indicator-' + id);
      if (ind) ind.classList.add('active');
      const field = document.getElementById('byok-' + id);
      if (field) field.classList.add('has-key');
      renderApiStatusBar();
    }
  } catch (e) {
    resultEl.textContent = 'Test failed — check connection';
    resultEl.style.color = 'var(--warning)';
  } finally {
    btn.textContent = 'Test Key';
    btn.disabled = false;
  }
}

function exportPdf() {
  const target = document.getElementById('riskTarget').textContent || 'Unknown';
  const score  = document.getElementById('gaugeScore').textContent || '--';
  const date   = new Date().toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric'
  });

  const style = document.createElement('style');
  style.id = 'pc-print';
  style.textContent =
    '@media print{' +
      'body > *:not(.tool-container){display:none!important}' +
      '.tool-container > *:not(#resultsContainer){display:none!important}' +
      '#resultsContainer{display:block!important}' +
      '.result-actions{display:none!important}' +
      '#terminalContainer{display:none!important}' +
      'body{background:#fff!important;color:#000!important}' +
      '.api-card{break-inside:avoid}' +
      '#pc-print-header{display:block!important}' +
    '}' +
    '#pc-print-header{display:none}';

  const header = document.createElement('div');
  header.id = 'pc-print-header';
  header.innerHTML =
    '<div style="font-family:monospace;font-size:13px;border-bottom:1px solid #ccc;padding-bottom:8px;margin-bottom:16px">' +
      '<strong>PhantomCheck</strong> by FutureStack Intelligence &nbsp;|&nbsp; ' +
      target + ' &nbsp;|&nbsp; Mode: ' + currentMode + ' &nbsp;|&nbsp; ' +
      'Threat Score: ' + score + ' &nbsp;|&nbsp; ' + date +
    '</div>';

  document.head.appendChild(style);
  document.getElementById('resultsContainer').insertAdjacentElement('afterbegin', header);

  window.print();

  setTimeout(function() {
    style.remove();
    header.remove();
  }, 1000);
}

function copyReport() {
  const modeOut = document.getElementById('modeOutput');
  const apiOut  = document.getElementById('apiResults');
  const target  = document.getElementById('riskTarget').textContent || '';
  const score   = document.getElementById('gaugeScore').textContent || '--';
  const date    = new Date().toISOString().split('T')[0];

  function stripHtml(el) {
    return (el ? el.innerText : '').replace(/\n{3,}/g, '\n\n').trim();
  }

  const text =
    'PHANTOMCHECK SCAN REPORT\n' +
    'Generated by FutureStack Intelligence\n' +
    '================================\n' +
    'Target: ' + target + '\n' +
    'Mode: ' + currentMode.toUpperCase() + '\n' +
    'Threat Score: ' + score + '/100\n' +
    'Date: ' + date + '\n' +
    '================================\n\n' +
    stripHtml(modeOut) + '\n\n' +
    '--- RAW SOURCE DATA ---\n\n' +
    stripHtml(apiOut);

  navigator.clipboard.writeText(text).then(function() {
    const btn = document.getElementById('copyReportBtn');
    const orig = btn.textContent;
    btn.textContent = '✓ Copied';
    setTimeout(function() { btn.textContent = orig; }, 2000);
  }).catch(function() {
    const btn = document.getElementById('copyReportBtn');
    btn.textContent = '✗ Failed';
    setTimeout(function() { btn.textContent = '📋 Copy'; }, 2000);
  });
}

function shareReport() {
  const input = document.getElementById('searchInput');
  const val   = input ? input.value.trim() : '';
  if (!val) return;

  const url = new URL(window.location.href);
  url.searchParams.set('t', val);
  url.searchParams.set('m', currentMode);
  url.hash = '';

  navigator.clipboard.writeText(url.toString()).then(function() {
    const btn = document.getElementById('shareReportBtn');
    const orig = btn.textContent;
    btn.textContent = '✓ Link copied';
    setTimeout(function() { btn.textContent = orig; }, 2500);
  }).catch(function() {
    const btn = document.getElementById('shareReportBtn');
    btn.textContent = '✗ Failed';
    setTimeout(function() { btn.textContent = '🔗 Share'; }, 2000);
  });
}
