function sanitise(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function terminalShow() {
  document.getElementById('terminalContainer').classList.remove('hidden');
  document.getElementById('resultsContainer').classList.add('hidden');
  document.getElementById('terminalLog').innerHTML = '';
  setTerminalTitle(currentMode);
}

function terminalSetCmd(target) {
  document.getElementById('terminalCmd').textContent =
    ' scan --target ' + target + ' --mode ' + currentMode;
}

function terminalLog(msg, status) {
  const line = document.createElement('div');
  line.className = 'log-line ' + (status || 'checking');

  const prefix = status === 'success' ? '[+]'
    : status === 'error'   ? '[!]'
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
  const arc   = document.getElementById('gaugeArc');
  const label = document.getElementById('gaugeScore');
  const total  = 251;
  const offset = total - (score / 100) * total;

  const color = score >= 70 ? 'var(--critical)'
    : score >= 40 ? 'var(--warning)'
    : 'var(--safe)';

  arc.style.transition = 'stroke-dashoffset 1.2s ease, stroke 0.4s ease';
  arc.style.stroke = color;
  arc.setAttribute('stroke-dashoffset', offset);
  label.textContent = score;
  label.style.fill  = color;

  const levelEl = document.getElementById('riskLevel');
  levelEl.textContent = score >= 70 ? 'HIGH RISK'
    : score >= 40 ? 'MODERATE RISK'
    : 'LOW RISK';
  levelEl.style.color = color;
}

function setRiskMeta(target, description) {
  document.getElementById('riskTarget').textContent      = target;
  document.getElementById('riskDescription').textContent = description;
}

function renderApiCards(results) {
  const container = document.getElementById('apiResults');
  container.innerHTML = '<h3 class="section-title">Raw Source Data</h3>';

  results.forEach(function(result) {
    const card     = document.createElement('div');
    card.className = 'api-card';
    card.id        = 'src-' + encodeURIComponent(result.source);

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

function renderAIOutput(parsed, mode) {
  const upsell = parsed.upsell && parsed.upsell !== 'none' ? UPSELL_DATA[parsed.upsell] : null;

  function severityColor(s) {
    return s === 'critical' ? 'var(--critical)'
      : s === 'warning'     ? 'var(--warning)'
      : 'var(--safe)';
  }

  function severityDot(s) {
    return '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' +
      severityColor(s) + ';margin-right:6px"></span>';
  }

  let html = '<div class="ai-output">';

  if (mode === 'explorer') {
    html +=
      '<div class="ai-verdict">' + sanitise(parsed.verdict) + '</div>' +
      '<div class="ai-findings">';

    (parsed.findings || []).forEach(function(f) {
      html +=
        '<div class="ai-finding-card">' +
          '<div class="ai-finding-header">' +
            severityDot(f.severity) +
            '<strong>' + sanitise(f.title) + '</strong>' +
            '<a class="ai-source-link" href="#src-' + encodeURIComponent(f.source) + '">' +
              'Source: ' + f.source +
            '</a>' +
          '</div>' +
          '<p class="ai-finding-body">' + sanitise(f.explanation) + '</p>' +
        '</div>';
    });

    html += '</div>';

    if (parsed.action_items && parsed.action_items.length) {
      html += '<div class="ai-actions"><h4>What should I do?</h4><ul>';
      parsed.action_items.forEach(function(a) {
        html += '<li>' + sanitise(a) + '</li>';
      });
      html += '</ul></div>';
    }
  }

  if (mode === 'analyst') {
    html +=
      '<div class="ai-verdict">' + sanitise(parsed.executive_summary) + '</div>' +
      '<p class="ai-rationale">' + sanitise(parsed.risk_score_rationale) + '</p>' +
      '<div class="ai-findings">';

    (parsed.findings || []).forEach(function(f) {
      html +=
        '<div class="ai-finding-card">' +
          '<div class="ai-finding-header">' +
            severityDot(f.severity) +
            '<strong>' + sanitise(f.title) + '</strong>' +
            '<a class="ai-source-link" href="#src-' + encodeURIComponent(f.source) + '">' +
              'Source: ' + f.source +
            '</a>' +
          '</div>' +
          '<p class="ai-finding-body">' + sanitise(f.detail) + '</p>' +
          '<div class="ai-recommendation">Recommendation: ' + sanitise(f.recommendation) + '</div>' +
        '</div>';
    });

    html += '</div>';

    if (parsed.threat_surface && parsed.threat_surface.length) {
      html += '<div class="ai-tags"><strong>Threat Surface:</strong>';
      parsed.threat_surface.forEach(function(t) {
        html += '<span class="ai-tag">' + sanitise(t) + '</span>';
      });
      html += '</div>';
    }

    if (parsed.compliance_flags && parsed.compliance_flags.length) {
      html += '<div class="ai-tags"><strong>Compliance Flags:</strong>';
      parsed.compliance_flags.forEach(function(c) {
        html += '<span class="ai-tag warning">' + sanitise(c) + '</span>';
      });
      html += '</div>';
    }
  }

  if (mode === 'operator') {
    html +=
      '<div class="ai-verdict mono">' + sanitise(parsed.assessment) + '</div>' +
      '<div class="ai-findings">';

    (parsed.findings || []).forEach(function(f) {
      const cves = (f.cve_refs || []).map(function(c) {
        return '<span class="ai-tag critical">' + sanitise(c) + '</span>';
      }).join('');
      const iocs = (f.iocs || []).map(function(i) {
        return '<span class="ai-tag">' + sanitise(i) + '</span>';
      }).join('');

      html +=
        '<div class="ai-finding-card">' +
          '<div class="ai-finding-header">' +
            severityDot(f.severity) +
            '<strong>' + sanitise(f.title) + '</strong>' +
            '<a class="ai-source-link" href="#src-' + encodeURIComponent(f.source) + '">' +
              'Source: ' + f.source +
            '</a>' +
          '</div>' +
          '<p class="ai-finding-body mono">' + sanitise(f.detail) + '</p>' +
          (f.exploit_notes ? '<div class="ai-exploit">Exploit notes: ' + sanitise(f.exploit_notes) + '</div>' : '') +
          (cves ? '<div class="ai-tags">' + cves + '</div>' : '') +
          (iocs ? '<div class="ai-tags">' + iocs + '</div>' : '') +
        '</div>';
    });

    html += '</div>';

    if (parsed.attack_vectors && parsed.attack_vectors.length) {
      html += '<div class="ai-tags"><strong>Attack Vectors:</strong>';
      parsed.attack_vectors.forEach(function(v) {
        html += '<span class="ai-tag warning">' + sanitise(v) + '</span>';
      });
      html += '</div>';
    }
  }

  if (upsell) {
    html +=
      '<div class="ai-upsell">' +
        '<div class="ai-upsell-title">' + upsell.title + '</div>' +
        '<div class="ai-upsell-body">' + upsell.body + '</div>' +
        (upsell.url
          ? '<a class="ai-upsell-cta" href="' + upsell.url + '" target="_blank" rel="noopener">' +
              upsell.cta +
            '</a>'
          : '<span class="ai-upsell-cta coming-soon">' + upsell.cta + ' — Coming Soon</span>'
        ) +
      '</div>';
  }

  html += '</div>';
  renderModeOutput(html);
}

// scan Chat UI

function renderChatSection() {
  var existing = document.getElementById('scanChatSection');
  if (existing) existing.remove();

  var section = document.createElement('div');
  section.id        = 'scanChatSection';
  section.className = 'scan-chat-section';

  section.innerHTML =
    '<button class="scan-chat-toggle" id="scanChatToggle" onclick="toggleChatSection()">' +
      '<span class="scan-chat-toggle-label">' +
        '<span class="scan-chat-icon">💬</span>' +
        'Ask about this scan' +
      '</span>' +
      '<span class="scan-chat-chevron" id="scanChatChevron">▼</span>' +
    '</button>' +

    '<div class="scan-chat-body hidden" id="scanChatBody">' +
      '<div class="scan-chat-messages" id="scanChatMessages">' +
        '<div class="scan-chat-msg assistant">' +
          '<span class="scan-chat-msg-text">' +
            'Scan loaded. Ask me anything about these results.' +
          '</span>' +
        '</div>' +
      '</div>' +

      '<div class="scan-chat-suggestions" id="scanChatSuggestions">' +
        '<button class="scan-chat-suggestion" onclick="useSuggestion(this)">What is the biggest risk here?</button>' +
        '<button class="scan-chat-suggestion" onclick="useSuggestion(this)">Is this target safe?</button>' +
        '<button class="scan-chat-suggestion" onclick="useSuggestion(this)">What should I do first?</button>' +
        '<button class="scan-chat-suggestion" onclick="useSuggestion(this)">Explain the findings in simple terms</button>' +
      '</div>' +

      '<div class="scan-chat-thinking hidden" id="scanChatThinking">' +
        '<span class="scan-chat-thinking-dot"></span>' +
        '<span class="scan-chat-thinking-dot"></span>' +
        '<span class="scan-chat-thinking-dot"></span>' +
      '</div>' +
      '<div class="scan-chat-input-row">' +
        '<input ' +
          'type="text" ' +
          'id="scanChatInput" ' +
          'class="scan-chat-input" ' +
          'placeholder="e.g. What is the biggest risk here?" ' +
          'autocomplete="off" ' +
          'spellcheck="false" ' +
          'onkeydown="handleChatKey(event)"' +
        '>' +
        '<button class="scan-chat-send" id="scanChatSend" onclick="submitChatMessage()">' +
          'Send' +
        '</button>' +
      '</div>' +
    '</div>';

  var anchor = document.getElementById('modeOutput');
  if (anchor && anchor.parentNode) {
    anchor.parentNode.insertBefore(section, anchor.nextSibling);
  }
}

function toggleChatSection() {
  var body    = document.getElementById('scanChatBody');
  var chevron = document.getElementById('scanChatChevron');
  if (!body) return;

  var isHidden = body.classList.toggle('hidden');
  chevron.style.transform = isHidden ? 'rotate(0deg)' : 'rotate(180deg)';

  if (!isHidden) {
    var input = document.getElementById('scanChatInput');
    if (input) input.focus();
  }
}

function appendChatMessage(role, text) {
  var container = document.getElementById('scanChatMessages');
  if (!container) return;

  var msg  = document.createElement('div');
  msg.className = 'scan-chat-msg ' + role;

  var span = document.createElement('span');
  span.className   = 'scan-chat-msg-text';
  span.textContent = text;

  msg.appendChild(span);
  container.appendChild(msg);
  container.scrollTop = container.scrollHeight;
}

function setChatThinking(active) {
  var thinking = document.getElementById('scanChatThinking');
  var send     = document.getElementById('scanChatSend');
  var input    = document.getElementById('scanChatInput');
  if (!thinking) return;

  if (active) {
    thinking.classList.remove('hidden');
    if (send)  send.disabled  = true;
    if (input) input.disabled = true;
    var container = document.getElementById('scanChatMessages');
    if (container) container.scrollTop = container.scrollHeight;
  } else {
    thinking.classList.add('hidden');
    if (send)  send.disabled  = false;
    if (input) {
      input.disabled = false;
      input.focus();
    }
  }
}

function handleChatKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    submitChatMessage();
  }
}

function submitChatMessage() {
  var input = document.getElementById('scanChatInput');
  if (!input) return;

  var text = input.value.trim();
  if (!text) return;

  input.value = '';
  appendChatMessage('user', text);
  sendChatMessage(text);
}

function useSuggestion(btn) {
  var text = btn.textContent.trim();
  var suggestions = document.getElementById('scanChatSuggestions');
  if (suggestions) suggestions.remove();
  appendChatMessage('user', text);
  sendChatMessage(text);
}
