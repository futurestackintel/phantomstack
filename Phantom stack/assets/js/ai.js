const AI_MODELS = {
  explorer: 'claude-haiku-4-5-20251001',
  analyst:  'claude-sonnet-4-6',
  operator: 'claude-sonnet-4-6'
};

const AI_PROMPTS = {
  explorer: `You are a plain-English security assistant helping non-technical users understand scan results.
Respond ONLY with a valid JSON object matching this exact schema. No prose, no markdown, no explanation outside the JSON.

{
  "verdict": "one sentence plain English summary of overall risk",
  "risk_level": "low | moderate | high",
  "findings": [
    {
      "title": "short plain English title",
      "explanation": "one to two sentences, no jargon, explain like talking to a small business owner",
      "source": "exact source name from raw data",
      "severity": "safe | warning | critical"
    }
  ],
  "action_items": ["plain English action the user should take"],
  "upsell": "none | digital_ghost | dark_web | ethical_hacking"
}

upsell rules: if personal data exposed pick digital_ghost. If dark web or breach mention pick dark_web. If general hacking exposure pick ethical_hacking. Otherwise none.`,

  analyst: `You are a professional security analyst writing a structured report for an IT manager or founder.
Respond ONLY with a valid JSON object matching this exact schema. No prose, no markdown, no explanation outside the JSON.

{
  "executive_summary": "two to three sentence professional summary",
  "risk_level": "low | moderate | high",
  "risk_score_rationale": "one sentence explaining the score",
  "findings": [
    {
      "title": "finding title",
      "detail": "technical detail with industry terms briefly defined in parentheses",
      "source": "exact source name from raw data",
      "severity": "safe | warning | critical",
      "recommendation": "specific remediation step"
    }
  ],
  "threat_surface": ["brief threat surface item"],
  "compliance_flags": ["any compliance concern e.g. GDPR, NDPR, PCI-DSS or empty array"],
  "upsell": "none | digital_ghost | dark_web | ethical_hacking"
}`,

  operator: `You are a penetration tester writing a technical briefing for another security researcher.
Respond ONLY with a valid JSON object matching this exact schema. No prose, no markdown, no explanation outside the JSON.

{
  "assessment": "one sentence technical verdict",
  "risk_level": "low | moderate | high",
  "findings": [
    {
      "title": "technical finding title",
      "cve_refs": ["CVE-XXXX-XXXX or empty array"],
      "iocs": ["IP, domain, hash or other indicator, or empty array"],
      "detail": "full technical detail, no hand-holding",
      "source": "exact source name from raw data",
      "severity": "safe | warning | critical",
      "exploit_notes": "exploitation notes or null"
    }
  ],
  "attack_vectors": ["identified attack vector"],
  "raw_toggle": true,
  "upsell": "none | digital_ghost | dark_web | ethical_hacking"
}`
};

const UPSELL_DATA = {
  digital_ghost: {
    title: 'Your data is out there.',
    body:  'Learn how to remove yourself from data brokers and lock down your digital footprint.',
    cta:   'Get The Digital Ghost',
    url:   'https://futurestackintel.gumroad.com/l/cwxnb'
  },
  dark_web: {
    title: 'Your details may be on the dark web.',
    body:  'Understand how dark web exposure works and what to do about it.',
    cta:   'Get Dark Web Explained',
    url:   'https://futurestackintel.gumroad.com/l/depbg'
  },
  agentic_fortress: {
    title: 'Build a system that protects and runs itself.',
    body:  'The complete security and automation playbook for developers and founders.',
    cta:   'Get The Agentic Fortress',
    url:   'https://futurestackintel.gumroad.com/l/pwghz'
  },
  ethical_hacking: {
    title: 'Want to understand how attackers think?',
    body:  'Learn ethical hacking with AI assistance from zero to first bug bounty.',
    cta:   'Get the AI Ethical Hacking Starter Kit',
    url:   null
  }
};

async function runAI(results, inputType, target, mode) {
  const key = localStorage.getItem('pc_key_claude');
  if (!key) {
    renderFallback(mode);
    return;
  }

  const outputEl = document.getElementById('modeOutput');
  outputEl.innerHTML = '<p style="color:var(--text-muted);font-size:0.9rem;padding:var(--space-lg)">[*] Running AI analysis...</p>';

  const payload = results.map(function(r) {
    return {
      source:   r.source,
      summary:  r.summary,
      severity: r.severity,
      score:    r.score || 0,
      raw:      r.raw || null
    };
  });

  const userMsg = 'Input type: ' + inputType + '\nTarget: ' + target +
    '\n\nRaw scan results:\n' + JSON.stringify(payload, null, 2);

  let data;
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         key,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true'
      },
      body: JSON.stringify({
        model:      AI_MODELS[mode],
        max_tokens: 1500,
        system:     AI_PROMPTS[mode],
        messages:   [{ role: 'user', content: userMsg }]
      })
    });
    data = await res.json();
  } catch (e) {
    outputEl.innerHTML = '<p style="color:var(--critical);padding:var(--space-lg)">[!] AI request failed — check your connection.</p>';
    return;
  }

  if (data.error) {
    outputEl.innerHTML = '<p style="color:var(--critical);padding:var(--space-lg)">[!] Claude error: ' + data.error.message + '</p>';
    return;
  }

  const raw = data.content && data.content[0] && data.content[0].text;
  if (!raw) {
    outputEl.innerHTML = '<p style="color:var(--critical);padding:var(--space-lg)">[!] Empty response from Claude.</p>';
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw.replace(/```json|```/g, '').trim());
  } catch (e) {
    outputEl.innerHTML = '<p style="color:var(--critical);padding:var(--space-lg)">[!] Could not parse AI response.</p>';
    return;
  }

  renderAIOutput(parsed, mode);
}

// ─── Scan Chat ────────────────────────────────────────────────────────────────

var _chatContext = null;
var _chatHistory = [];
var _chatMaxTurns = 6;

function initScanChat(results, inputType, target, mode) {
  _chatHistory = [];

  var payload = results.map(function(r) {
    return {
      source:   r.source,
      summary:  r.summary,
      severity: r.severity,
      score:    r.score || 0
    };
  });

  _chatContext = {
    system: buildChatSystemPrompt(payload, inputType, target, mode),
    key:    localStorage.getItem('pc_key_claude')
  };

  renderChatSection();
}

function buildChatSystemPrompt(payload, inputType, target, mode) {
  var modeLabel = mode === 'explorer' ? 'plain English (non-technical)'
    : mode === 'analyst' ? 'professional analyst'
    : 'technical / penetration tester';

  return 'You are a security assistant answering questions about a completed OSINT scan.\n' +
    'Scan target: ' + target + '\n' +
    'Input type: ' + inputType + '\n' +
    'Output mode: ' + modeLabel + '\n\n' +
    'Scan findings summary:\n' +
    JSON.stringify(payload, null, 2) + '\n\n' +
    'Answer the user\'s questions about this scan concisely and accurately. ' +
    'Stay grounded in the scan data above. If something is not covered by the scan data, say so. ' +
    'Do not output JSON. Respond in plain prose matching the output mode tone.';
}

async function sendChatMessage(userText) {
  if (!_chatContext) return;

  var key = _chatContext.key;
  if (!key) {
    appendChatMessage('assistant', '[!] No Claude API key found. Add it in Settings.');
    return;
  }

  _chatHistory.push({ role: 'user', content: userText });

  if (_chatHistory.length > _chatMaxTurns * 2) {
    _chatHistory = _chatHistory.slice(-(_chatMaxTurns * 2));
  }

  setChatThinking(true);

  var data;
  try {
    var res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         key,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true'
      },
      body: JSON.stringify({
        model:      'claude-haiku-4-5-20251001',
        max_tokens: 1000,
        system:     _chatContext.system,
        messages:   _chatHistory
      })
    });
    data = await res.json();
  } catch (e) {
    setChatThinking(false);
    appendChatMessage('assistant', '[!] Request failed — check your connection.');
    _chatHistory.pop();
    return;
  }

  setChatThinking(false);

  if (data.error) {
    appendChatMessage('assistant', '[!] Claude error: ' + data.error.message);
    _chatHistory.pop();
    return;
  }

  var reply = data.content && data.content[0] && data.content[0].text;
  if (!reply) {
    appendChatMessage('assistant', '[!] Empty response.');
    _chatHistory.pop();
    return;
  }

  _chatHistory.push({ role: 'assistant', content: reply });
  appendChatMessage('assistant', reply);
}

function clearScanChat() {
  _chatContext  = null;
  _chatHistory  = [];
  var el = document.getElementById('scanChatSection');
  if (el) el.remove();
}
