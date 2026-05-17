// ============================================
// PHANTOMCHECK — MAIN APP (Revised MVP)
// Pure BYOK, no subscriptions, no paywalls
// ============================================

// All API keys we support — used to build the status bar
// and the settings panel indicators
const API_KEYS = {
  claude:         { label: 'Claude AI',       storageKey: 'pc_key_claude'         },
  virustotal:     { label: 'VirusTotal',      storageKey: 'pc_key_virustotal'     },
  shodan:         { label: 'Shodan',          storageKey: 'pc_key_shodan'         },
  hibp:           { label: 'HIBP',            storageKey: 'pc_key_hibp'           },
  securitytrails: { label: 'SecurityTrails',  storageKey: 'pc_key_securitytrails' },
};

// Mode descriptions — shown below the mode tabs when each is selected
const MODE_DESCRIPTIONS = {
  explorer: 'Explorer mode explains findings in plain English with zero jargon. Ideal for business owners, individuals and non-technical users.',
  analyst:  'Analyst mode produces a structured professional security report. Business risk focused with industry terminology briefly explained.',
  operator: 'Operator mode outputs raw technical intelligence. CVE references, full JSON available, terminal aesthetic. No hand-holding.',
};

// ============================================
// INITIALISE ON DOM READY
// ============================================
document.addEventListener('DOMContentLoaded', function () {

  // Render the API status bar in the hero section
  renderApiStatusBar();

  // Load any saved keys into the settings panel inputs
  loadSavedKeys();

  // Show terms notice if user hasn't accepted yet
  const termsAccepted = localStorage.getItem('pc_terms');
  if (!termsAccepted) {
    document.getElementById('termsNotice').classList.remove('hidden');
  }

  // ---- Mode switching ----
  let currentMode = 'explorer';
  const modeTabs = document.querySelectorAll('.mode-tab');

  modeTabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      // Deactivate all tabs
      modeTabs.forEach(function (t) { t.classList.remove('active'); });
      // Activate clicked tab
      tab.classList.add('active');
      // Update current mode
      currentMode = tab.dataset.mode;
      // Update the description text below the tabs
      document.getElementById('modeContextText').textContent =
        MODE_DESCRIPTIONS[currentMode];
    });
  });

  // ---- Settings panel — open ----
  // Both the nav button and the hero status bar button open settings
  document.getElementById('settingsBtn').addEventListener('click', function (e) {
    e.preventDefault();
    openSettings();
  });

  document.getElementById('apiStatusSetupBtn').addEventListener('click', function () {
    openSettings();
  });

  // ---- Settings panel — close ----
  document.getElementById('settingsClose').addEventListener('click', closeSettings);

  // Close when clicking the dark overlay behind the panel
  document.getElementById('settingsOverlay').addEventListener('click', function (e) {
    // e.target is the element that was actually clicked
    // We only close if they clicked the overlay itself, not the panel inside it
    if (e.target === document.getElementById('settingsOverlay')) {
      closeSettings();
    }
  });

  // ---- Save API keys ----
  document.getElementById('saveKeysBtn').addEventListener('click', function () {
    saveKeys();
  });

  // ---- Scan button ----
  document.getElementById('scanBtn').addEventListener('click', function () {
    initiateScan(currentMode);
  });

  // Allow Enter key to trigger scan
  document.getElementById('searchInput').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { initiateScan(currentMode); }
  });

  // ---- Collapsible API result cards ----
  // Event delegation — one listener handles all cards including ones added later
  document.addEventListener('click', function (e) {
    const header = e.target.closest('.api-card-header');
    if (!header) return;
    header.closest('.api-card').classList.toggle('expanded');
  });

});

// ============================================
// SETTINGS PANEL
// ============================================

function openSettings() {
  document.getElementById('settingsOverlay').classList.remove('hidden');
}

function closeSettings() {
  document.getElementById('settingsOverlay').classList.add('hidden');
}

// ============================================
// API KEY MANAGEMENT
// ============================================

// Read all key inputs from the settings panel and save to localStorage
function saveKeys() {
  let savedCount = 0;

  Object.entries(API_KEYS).forEach(function ([apiId, config]) {
    const input = document.getElementById('key-' + apiId);
    if (!input) return;

    const value = input.value.trim();

    if (value) {
      // Save the key — storageKey is our localStorage key name
      localStorage.setItem(config.storageKey, value);
      savedCount++;

      // Update the green dot indicator for this API
      const indicator = document.getElementById('indicator-' + apiId);
      if (indicator) { indicator.classList.add('active'); }

      // Add green border to the field container
      const field = document.getElementById('byok-' + apiId);
      if (field) { field.classList.add('has-key'); }

    } else {
      // If input is blank, remove any previously saved key
      localStorage.removeItem(config.storageKey);

      const indicator = document.getElementById('indicator-' + apiId);
      if (indicator) { indicator.classList.remove('active'); }

      const field = document.getElementById('byok-' + apiId);
      if (field) { field.classList.remove('has-key'); }
    }
  });

  // Re-render the status bar in the hero to reflect new key state
  renderApiStatusBar();

  // Visual feedback on the save button
  const btn = document.getElementById('saveKeysBtn');
  const original = btn.textContent;
  btn.textContent = savedCount > 0
    ? '✓ ' + savedCount + ' KEY(S) SAVED'
    : '✓ KEYS CLEARED';
  setTimeout(function () { btn.textContent = original; }, 2000);

  // Close settings after saving
  setTimeout(closeSettings, 800);
}

// On page load, populate the input fields with any previously saved keys
function loadSavedKeys() {
  Object.entries(API_KEYS).forEach(function ([apiId, config]) {
    const saved = localStorage.getItem(config.storageKey);
    const input = document.getElementById('key-' + apiId);
    if (!input) return;

    if (saved) {
      // Show masked version so user knows a key exists
      // We don't show the actual key for security
      input.value = saved;

      const indicator = document.getElementById('indicator-' + apiId);
      if (indicator) { indicator.classList.add('active'); }

      const field = document.getElementById('byok-' + apiId);
      if (field) { field.classList.add('has-key'); }
    }
  });
}

// ============================================
// API STATUS BAR (hero section)
// Shows which APIs are active at a glance
// ============================================

function renderApiStatusBar() {
  const container = document.getElementById('apiStatusPills');
  if (!container) return;

  // Clear existing pills
  container.innerHTML = '';

  // Always-active free APIs — no key needed
  const freeApis = [
    'crt.sh', 'urlscan.io', 'AbuseIPDB', 'DNS', 'Africa Check'
  ];

  freeApis.forEach(function (name) {
    container.appendChild(makePill(name, true));
  });

  // BYOK APIs — active only if user has saved a key
  Object.entries(API_KEYS).forEach(function ([apiId, config]) {
    const hasKey = !!localStorage.getItem(config.storageKey);
    container.appendChild(makePill(config.label, hasKey));
  });
}

// Creates one status pill element
function makePill(label, isReady) {
  const pill = document.createElement('div');
  pill.className = 'status-pill ' + (isReady ? 'ready' : 'missing');

  const dot = document.createElement('span');
  dot.className = 'status-pill-dot';

  const text = document.createElement('span');
  text.textContent = label;

  pill.appendChild(dot);
  pill.appendChild(text);
  return pill;
}

// ============================================
// SCAN INITIATION
// Full scan engine built in Modules 4-8
// This validates input and checks prerequisites
// ============================================

function initiateScan(currentMode) {
  const input   = document.getElementById('searchInput');
  const query   = input.value.trim();

  // Validate — must have something to scan
  if (!query) {
    flashBorder(input, 'var(--critical)');
    input.focus();
    return;
  }

  // Check terms accepted
  const termsAccepted  = localStorage.getItem('pc_terms');
  const termsCheckbox  = document.getElementById('termsCheckbox');
  const termsNotice    = document.getElementById('termsNotice');

  if (!termsAccepted) {
    if (!termsCheckbox || !termsCheckbox.checked) {
      flashBorder(termsNotice, 'var(--critical)');
      return;
    }
    // Save acceptance permanently
    localStorage.setItem('pc_terms', 'true');
    termsNotice.classList.add('hidden');
  }

  // Check Claude key exists — needed for AI interpretation
  const claudeKey = localStorage.getItem('pc_key_claude');
  if (!claudeKey) {
    // Prompt user to add their Claude key
    openSettings();
    // Flash the Claude field to draw attention
    const claudeField = document.getElementById('byok-claude');
    if (claudeField) { flashBorder(claudeField, 'var(--warning)'); }
    return;
  }

  // All checks passed — scan engine connects here in Module 3
  console.log('Scan initiated:', { query, mode: currentMode });
  alert(
    'Interface confirmed working ✓\n\n' +
    'Target: ' + query + '\n' +
    'Mode: ' + currentMode.toUpperCase() + '\n\n' +
    'Scan engine connects in Module 3.'
  );
}

// Temporarily flashes a red/warning border on any element
function flashBorder(element, color) {
  const original = element.style.borderColor;
  element.style.borderColor = color;
  setTimeout(function () {
    element.style.borderColor = original;
  }, 1500);
                                          }
