function terminalShow() {
  document.getElementById('terminalContainer').classList.remove('hidden');
  document.getElementById('resultsContainer').classList.add('hidden');
  document.getElementById('terminalLog').innerHTML = '';
}

function terminalSetCmd(target) {
  document.getElementById('terminalCmd').textContent =
    ' scan --target ' + target + ' --mode ' + currentMode;
}

function terminalLog(msg, status) {
  const line = document.createElement('div');
  line.className = 'log-line ' + (status || 'checking');

  const prefix = status === 'success' ? '[+]'
    : status === 'error' ? '[!]'
    : status === 'warning' ? '[~]'
    : '[*]';

  line.textContent = prefix + ' ' + msg;
  document.getElementById('terminalLog').appendChild(line);

  const body = document.getElementById('terminalBody');
  body.scrollTop = body.scrollHeight;
}

function terminalDone() {
  document.getElementById('terminalContainer').classList.add('hidden');
  document.getElementById('resultsContainer').classList.remove('hidden');
}

function gaugeAnimate(score) {
  const arc = document.getElementById('gaugeArc');
  const label = document.getElementById('gaugeScore');
  const total = 251;
  const offset = total - (score / 100) * total;

  const color = score >= 70 ? 'var(--critical)'
    : score >= 40 ? 'var(--warning)'
    : 'var(--safe)';

  arc.style.transition = 'stroke-dashoffset 1.2s ease, stroke 0.4s ease';
  arc.style.stroke = color;
  arc.setAttribute('stroke-dashoffset', offset);
  label.textContent = score;
  label.style.fill = color;

  const levelEl = document.getElementById('riskLevel');
  levelEl.textContent = score >= 70 ? 'HIGH RISK'
    : score >= 40 ? 'MODERATE RISK'
    : 'LOW RISK';
  levelEl.style.color = color;
}

function setRiskMeta(target, description) {
  document.getElementById('riskTarget').textContent = target;
  document.getElementById('riskDescription').textContent = description;
}

function renderApiCards(results) {
  const container = document.getElementById('apiResults');
  container.innerHTML = '<h3 class="section-title">Raw Source Data</h3>';

  results.forEach(function(result) {
    const card = document.createElement('div');
    card.className = 'api-card';

    const severity = result.severity || 'safe';

    card.innerHTML =
      '<div class="api-card-header">' +
        '<div class="api-card-left">' +
          '<div class="api-status-dot ' + severity + '"></div>' +
          '<div>' +
            '<div class="api-name">' + result.source + '</div>' +
            '<div class="api-summary">' + result.summary + '</div>' +
          '</div>' +
        '</div>' +
        '<span class="api-card-toggle">▼</span>' +
      '</div>' +
      '<div class="api-card-body">' +
        renderCardBody(result) +
      '</div>';

    container.appendChild(card);
  });
}

function renderCardBody(result) {
  if (result.error) {
    return '<span style="color:var(--critical)">' + result.error + '</span>';
  }

  if (result.raw && typeof result.raw === 'object') {
    return '<pre style="font-size:0.78rem;overflow-x:auto;white-space:pre-wrap;color:var(--text-secondary)">' +
      JSON.stringify(result.raw, null, 2) +
      '</pre>';
  }

  return '<span style="color:var(--text-muted)">No data returned.</span>';
}

function renderModeOutput(html) {
  document.getElementById('modeOutput').innerHTML = html;
}

function scanBtnState(scanning) {
  const btn = document.getElementById('scanBtn');
  btn.disabled = scanning;
  btn.querySelector('.scan-btn-text').textContent = scanning ? 'SCANNING' : 'SCAN';
}
