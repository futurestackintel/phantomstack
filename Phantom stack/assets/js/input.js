const INPUT_TYPES = {
  EMAIL:   'EMAIL',
  IP:      'IP',
  DOMAIN:  'DOMAIN',
  UNKNOWN: 'UNKNOWN'
};

const BLOCKED_TLDS = [
  '.mil', '.gov', '.mod.uk', '.mil.au', '.gc.ca'
];

const BLOCKED_KEYWORDS = [
  'pentagon', 'whitehouse', 'cia.gov', 'nsa.gov',
  'fbi.gov', 'dhs.gov', 'army.mil', 'navy.mil'
];

const MODE_SUGGESTIONS = {
  EMAIL:  'explorer',
  IP:     'operator',
  DOMAIN: 'analyst'
};

const BADGE_LABELS = {
  EMAIL:   'EMAIL ADDRESS',
  IP:      'IP ADDRESS',
  DOMAIN:  'DOMAIN',
  UNKNOWN: 'ENTER TARGET'
};

function detectInputType(raw) {
  const val = raw.trim().toLowerCase();
  if (!val) return INPUT_TYPES.UNKNOWN;
  if (isEmail(val))  return INPUT_TYPES.EMAIL;
  if (isIP(val))     return INPUT_TYPES.IP;
  if (isDomain(val)) return INPUT_TYPES.DOMAIN;
  return INPUT_TYPES.UNKNOWN;
}

function isEmail(val) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
}

function isIP(val) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(val) &&
    val.split('.').every(n => parseInt(n) <= 255);
}

function isDomain(val) {
  return /^([a-z0-9-]+\.)+[a-z]{2,}$/.test(val);
}

function isBlocked(val) {
  const lower = val.toLowerCase();
  if (BLOCKED_TLDS.some(tld => lower.endsWith(tld))) return true;
  if (BLOCKED_KEYWORDS.some(kw => lower.includes(kw))) return true;
  return false;
}

function validateInput(val) {
  if (!val) return { ok: false, msg: 'Enter a domain, email or IP address.' };

  if (isBlocked(val)) {
    return {
      ok: false,
      msg: 'Government and military targets are blocked on PhantomCheck.'
    };
  }

  const type = detectInputType(val);

  if (type === INPUT_TYPES.UNKNOWN) {
    return {
      ok: false,
      msg: 'Not recognised. Enter a domain (site.com), email or IP address.'
    };
  }

  if (type === INPUT_TYPES.IP) {
    const parts = val.split('.');
    const first = parseInt(parts[0]);
    if (first === 10 || first === 127 ||
       (first === 172 && parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31) ||
       (first === 192 && parseInt(parts[1]) === 168)) {
      return { ok: false, msg: 'Private IP ranges cannot be scanned.' };
    }
  }

  return { ok: true, msg: '', type };
}

function getRateLimit() {
  const stored = localStorage.getItem('pc_rl');
  if (!stored) return { count: 0, date: todayStr() };
  return JSON.parse(stored);
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function checkRateLimit() {
  let rl = getRateLimit();
  if (rl.date !== todayStr()) rl = { count: 0, date: todayStr() };
  return rl.count < 5;
}

function incrementRateLimit() {
  let rl = getRateLimit();
  if (rl.date !== todayStr()) rl = { count: 0, date: todayStr() };
  rl.count++;
  localStorage.setItem('pc_rl', JSON.stringify(rl));
}

function scansRemaining() {
  let rl = getRateLimit();
  if (rl.date !== todayStr()) return 5;
  return Math.max(0, 5 - rl.count);
    }
