const CACHE_PREFIX = 'pc_cache_';
const CACHE_TTL = 86400000;

function cacheKey(target, type) {
  return CACHE_PREFIX + type + '_' + target.toLowerCase().replace(/[^a-z0-9.@_-]/g, '');
}

function cacheGet(target, type) {
  const key = cacheKey(target, type);
  const raw = localStorage.getItem(key);
  if (!raw) return null;
  const entry = JSON.parse(raw);
  if (Date.now() - entry.ts > CACHE_TTL) {
    localStorage.removeItem(key);
    return null;
  }
  return entry.data;
}

function cacheSet(target, type, data) {
  const key = cacheKey(target, type);
  localStorage.setItem(key, JSON.stringify({ ts: Date.now(), data }));
}

function cacheClear() {
  Object.keys(localStorage)
    .filter(k => k.startsWith(CACHE_PREFIX))
    .forEach(k => localStorage.removeItem(k));
}
