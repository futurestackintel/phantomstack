const MODE_TERMINAL_TITLES = {
  explorer: 'phantomcheck — plain english analysis',
  analyst:  'phantomcheck — professional report mode',
  operator: 'phantomcheck — operator intelligence mode',
};

const MODE_FALLBACKS = {
  explorer:
    '<div class="mode-fallback">' +
      '<div class="mode-fallback-icon">👁</div>' +
      '<div class="mode-fallback-title">Explorer Mode — AI Key Required</div>' +
      '<div class="mode-fallback-body">Explorer mode uses Claude AI to translate these scan results into plain English with zero jargon. Add your Claude API key in the API Keys settings to unlock this.</div>' +
      '<div class="mode-fallback-what">What you get with Explorer mode:</div>' +
      '<ul class="mode-fallback-list">' +
        '<li>A plain English verdict on your target</li>' +
        '<li>Each finding explained like you\'re talking to a friend</li>' +
        '<li>Clear action steps — no technical knowledge needed</li>' +
      '</ul>' +
      '<button class="mode-fallback-btn" onclick="openSettings()">Add Claude Key →</button>' +
    '</div>',

  analyst:
    '<div class="mode-fallback">' +
      '<div class="mode-fallback-icon">📊</div>' +
      '<div class="mode-fallback-title">Analyst Mode — AI Key Required</div>' +
      '<div class="mode-fallback-body">Analyst mode produces a structured professional security report with executive summary, compliance flags, and remediation recommendations. Add your Claude API key to unlock this.</div>' +
      '<div class="mode-fallback-what">What you get with Analyst mode:</div>' +
      '<ul class="mode-fallback-list">' +
        '<li>Executive summary suitable for board or management reporting</li>' +
        '<li>Threat surface mapping with compliance flags (GDPR, NDPR, PCI-DSS)</li>' +
        '<li>Specific remediation steps per finding</li>' +
      '</ul>' +
      '<button class="mode-fallback-btn" onclick="openSettings()">Add Claude Key →</button>' +
    '</div>',

  operator:
    '<div class="mode-fallback">' +
      '<div class="mode-fallback-icon">⚡</div>' +
      '<div class="mode-fallback-title">Operator Mode — AI Key Required</div>' +
      '<div class="mode-fallback-body">Operator mode delivers raw technical intelligence with CVE references, IOCs, attack vectors and exploit notes. Built for penetration testers and security researchers. Add your Claude API key to unlock.</div>' +
      '<div class="mode-fallback-what">What you get with Operator mode:</div>' +
      '<ul class="mode-fallback-list">' +
        '<li>CVE references tied directly to findings</li>' +
        '<li>IOCs — IPs, domains, hashes extracted from raw data</li>' +
        '<li>Attack vectors and exploit notes where applicable</li>' +
      '</ul>' +
      '<button class="mode-fallback-btn" onclick="openSettings()">Add Claude Key →</button>' +
    '</div>',
};

function saveMode(mode) {
  localStorage.setItem('pc_mode', mode);
}

function loadSavedMode() {
  const saved = localStorage.getItem('pc_mode');
  if (!saved || !MODE_DESCRIPTIONS[saved]) return;
  currentMode = saved;
  document.querySelectorAll('.mode-tab').forEach(function(tab) {
    tab.classList.remove('active');
    if (tab.dataset.mode === saved) tab.classList.add('active');
  });
  document.getElementById('modeContextText').textContent =
    MODE_DESCRIPTIONS[saved];
}

function setTerminalTitle(mode) {
  const el = document.getElementById('terminalTitle');
  if (el) el.textContent = MODE_TERMINAL_TITLES[mode] || MODE_TERMINAL_TITLES.explorer;
}

function renderFallback(mode) {
  renderModeOutput(MODE_FALLBACKS[mode] || MODE_FALLBACKS.explorer);
}
