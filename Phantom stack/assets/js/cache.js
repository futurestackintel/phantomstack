const CACHE_PREFIX = 'pc_cache_';
const CACHE_TTL    = 86400000;

function cacheKey(target, type) {
  return CACHE_PREFIX + type + '_' +
    target.toLowerCase().replace(/[^a-z0-9.@_-]/g, '');
}

function cacheGet(target, type) {
  const key = cacheKey(target, type);
  const raw = localStorage.getItem(key);
  if (!raw) return null;
  let entry;
  try {
    entry = JSON.parse(raw);
  } catch (e) {
    localStorage.removeItem(key);
    return null;
  }
  if (Date.now() - entry.ts > CACHE_TTL) {
    localStorage.removeItem(key);
    return null;
  }
  return entry;
}

function cacheSet(target, type, data) {
  const key = cacheKey(target, type);
  localStorage.setItem(key, JSON.stringify({ ts: Date.now(), data }));
}

function cacheClear() {
  Object.keys(localStorage)
    .filter(function(k) { return k.startsWith(CACHE_PREFIX); })
    .forEach(function(k) { localStorage.removeItem(k); });
}

function cacheCleanExpired() {
  Object.keys(localStorage)
    .filter(function(k) { return k.startsWith(CACHE_PREFIX); })
    .forEach(function(k) {
      const raw = localStorage.getItem(k);
      if (!raw) return;
      let entry;
      try {
        entry = JSON.parse(raw);
      } catch (e) {
        localStorage.removeItem(k);
        return;
      }
      if (Date.now() - entry.ts > CACHE_TTL) localStorage.removeItem(k);
    });
}

function cacheAge(ts) {
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60000);
  const hrs  = Math.floor(diff / 3600000);
  if (mins < 1)  return 'just now';
  if (mins < 60) return mins + ' minute' + (mins === 1 ? '' : 's') + ' ago';
  if (hrs  < 24) return hrs  + ' hour'   + (hrs  === 1 ? '' : 's') + ' ago';
  return Math.floor(hrs / 24) + ' days ago';
}
