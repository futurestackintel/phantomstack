const API_KEYS = {
  claude:         { label: 'Claude AI',      storageKey: 'pc_key_claude'         },
  virustotal:     { label: 'VirusTotal',     storageKey: 'pc_key_virustotal'     },
  shodan:         { label: 'Shodan',         storageKey: 'pc_key_shodan'         },
  hibp:           { label: 'HIBP',           storageKey: 'pc_key_hibp'           },
  securitytrails: { label: 'SecurityTrails', storageKey: 'pc_key_securitytrails' },
};

const MODE_DESCRIPTIONS = {
  explorer: 'Explorer mode explains findings in plain English with zero jargon. Ideal for business owners, individuals and non-technical users.',
  analyst:  'Analyst mode produces a structured professional security report. Business risk focused with industry terminology briefly explained.',
  operator: 'Operator mode outputs raw technical intelligence. CVE references, full JSON available, terminal aesthetic. No hand-holding.',
};

let currentMode = 'explorer';

document.addEventListener('DOMContentLoaded', function() {
  renderApiStatusBar();
  loadSavedKeys();
  updateScansRemaining();

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

  const claudeKey = localStorage.getItem('pc_key_claude');
  if (!claudeKey) {
    openSettings();
    const field = document.getElementById('byok-claude');
    if (field) flashBorder(field, 'var(--warning)');
    return;
  }

  incrementRateLimit();
  updateScansRemaining();

  // Hands off to scanner — built in Module 4
  console.log('Scan ready:', { target: val, type: validation.type, mode: currentMode });
  alert('Input intelligence working. \nTarget: ' + val +
    '\nType: ' + validation.type + '\nMode: ' + currentMode.toUpperCase());
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
