async function apiCrtSh(domain) {
  const source = 'crt.sh';
  try {
    const res = await fetch(
      'https://crt.sh/?q=' + encodeURIComponent(domain) + '&output=json',
      { signal: AbortSignal.timeout(10000) }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();

    const names = [...new Set(
      data.map(function(e) { return e.name_value; })
          .join('\n')
          .split('\n')
          .map(function(s) { return s.trim().toLowerCase(); })
          .filter(function(s) { return s && !s.startsWith('*'); })
    )].slice(0, 50);

    return {
      source,
      severity: names.length > 10 ? 'warning' : 'safe',
      summary:  names.length + ' subdomains found via certificate transparency',
      raw:      { subdomains: names, total_certs: data.length },
      score:    Math.min(names.length * 2, 20)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}

async function apiUrlscan(domain) {
  const source = 'urlscan.io';
  try {
    const res = await fetch(
      'https://urlscan.io/api/v1/search/?q=domain:' + encodeURIComponent(domain) + '&size=5',
      { signal: AbortSignal.timeout(10000) }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data    = await res.json();
    const results = data.results || [];
    const malicious = results.filter(function(r) {
      return r.verdicts && r.verdicts.overall && r.verdicts.overall.malicious;
    }).length;

    return {
      source,
      severity: malicious > 0 ? 'critical' : 'safe',
      summary:  results.length + ' scans found' +
        (malicious > 0 ? ', ' + malicious + ' flagged malicious' : ''),
      raw: results.map(function(r) {
        return {
          url:       r.page && r.page.url,
          ip:        r.page && r.page.ip,
          country:   r.page && r.page.country,
          malicious: r.verdicts && r.verdicts.overall && r.verdicts.overall.malicious,
          scanned:   r.task && r.task.time
        };
      }),
      score: malicious * 20
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}

async function apiAbuseIPDB(ip) {
  const source = 'AbuseIPDB';
  try {
    const res = await fetch(
      'https://api.abuseipdb.com/api/v2/check?ipAddress=' +
        encodeURIComponent(ip) + '&maxAgeInDays=90',
      {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000)
      }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const d    = data.data || {};
    const score    = d.abuseConfidenceScore || 0;
    const severity = score >= 80 ? 'critical' : score >= 30 ? 'warning' : 'safe';

    return {
      source,
      severity,
      summary: 'Abuse confidence: ' + score + '% — ' +
        (d.totalReports || 0) + ' reports in 90 days',
      raw: {
        ip:            d.ipAddress,
        abuse_score:   score,
        total_reports: d.totalReports,
        country:       d.countryCode,
        isp:           d.isp,
        usage_type:    d.usageType,
        is_tor:        d.isTor,
        last_reported: d.lastReportedAt
      },
      score: Math.min(score, 40)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}

async function apiDns(target) {
  const source = 'DNS Lookup';
  try {
    const types   = ['A', 'MX', 'TXT', 'NS', 'AAAA'];
    const records = {};

    await Promise.all(types.map(async function(type) {
      const res = await fetch(
        'https://dns.google/resolve?name=' + encodeURIComponent(target) + '&type=' + type,
        { signal: AbortSignal.timeout(8000) }
      );
      if (!res.ok) return;
      const data = await res.json();
      if (data.Answer && data.Answer.length) {
        records[type] = data.Answer.map(function(a) { return a.data; });
      }
    }));

    const hasTxt = !!records.TXT;
    const spf    = hasTxt && records.TXT.some(function(t) { return t.includes('v=spf1'); });
    const dmarc  = hasTxt && records.TXT.some(function(t) { return t.includes('v=DMARC1'); });
    const issues = [];
    if (!spf)   issues.push('No SPF record — domain spoofable for email phishing');
    if (!dmarc) issues.push('No DMARC record — no email authentication policy');

    return {
      source,
      severity: issues.length >= 2 ? 'warning' : 'safe',
      summary:  Object.keys(records).join(', ') + ' records found' +
        (issues.length ? ' — ' + issues.length + ' email security gaps' : ''),
      raw:   { records, issues },
      score: issues.length * 8
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}

async function apiAfricaCheck(target) {
  const source   = 'Africa Regional Check';
  const isNg     = target.endsWith('.ng') || target.endsWith('.com.ng');
  const isZa     = target.endsWith('.co.za') || target.endsWith('.za');
  const findings = [];
  let score      = 0;

  if (isNg) findings.push('Nigerian domain (.ng) — checking regional exposure');
  if (isZa) findings.push('South African domain (.za) — checking regional exposure');

  try {
    const res  = await fetch(
      'https://dns.google/resolve?name=' + encodeURIComponent(target) + '&type=A',
      { signal: AbortSignal.timeout(8000) }
    );
    const data = await res.json();
    const ips  = data.Answer ? data.Answer.map(function(a) { return a.data; }) : [];

    if (ips.length) findings.push('Resolves to: ' + ips.join(', '));

    const africanRanges = ['41.', '102.', '105.', '196.', '197.', '154.'];
    const africanIp     = ips.some(function(ip) {
      return africanRanges.some(function(r) { return ip.startsWith(r); });
    });

    if (africanIp) {
      findings.push('Hosted on African IP range — verify datacenter security posture');
      score += 5;
    }

    if (isNg || isZa) score += 5;

    return {
      source,
      severity: score > 5 ? 'warning' : 'safe',
      summary:  (isNg || isZa)
        ? 'Regional TLD detected — ' + findings.length + ' findings'
        : 'Non-African TLD — basic regional check only',
      raw: { target, findings, african_ip: africanIp, ips },
      score
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}

async function apiVirusTotal(target, type) {
  const source = 'VirusTotal';
  const key    = localStorage.getItem('pc_key_virustotal');
  if (!key) return { source, severity: 'safe', summary: 'No API key — skipped', score: 0 };

  const endpoint = type === INPUT_TYPES.IP
    ? 'https://www.virustotal.com/api/v3/ip_addresses/' + encodeURIComponent(target)
    : 'https://www.virustotal.com/api/v3/domains/' + encodeURIComponent(target);

  try {
    const res = await fetch(endpoint, {
      headers: { 'x-apikey': key },
      signal:  AbortSignal.timeout(10000)
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data  = await res.json();
    const attrs = (data.data && data.data.attributes) || {};
    const stats = attrs.last_analysis_stats || {};

    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const severity   = malicious > 3 ? 'critical'
      : malicious > 0 || suspicious > 0 ? 'warning'
      : 'safe';

    return {
      source,
      severity,
      summary: malicious + ' malicious · ' + suspicious + ' suspicious out of ' +
        ((stats.harmless || 0) + malicious + suspicious + (stats.undetected || 0)) + ' vendors',
      raw:   { stats, reputation: attrs.reputation },
      score: Math.min(malicious * 8 + suspicious * 3, 40)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Error: ' + e.message, error: e.message, score: 0 };
  }
}

async function apiShodan(target, type) {
  const source = 'Shodan';
  const key    = localStorage.getItem('pc_key_shodan');
  if (!key) return { source, severity: 'safe', summary: 'No API key — skipped', score: 0 };

  const endpoint = type === INPUT_TYPES.IP
    ? 'https://api.shodan.io/shodan/host/' + encodeURIComponent(target) + '?key=' + key
    : 'https://api.shodan.io/dns/resolve?hostnames=' + encodeURIComponent(target) + '&key=' + key;

  try {
    const res = await fetch(endpoint, { signal: AbortSignal.timeout(12000) });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data  = await res.json();
    const ports = data.ports || [];
    const vulns = data.vulns ? Object.keys(data.vulns) : [];

    return {
      source,
      severity: vulns.length > 0 ? 'critical' : ports.length > 5 ? 'warning' : 'safe',
      summary:  ports.length + ' open ports · ' + vulns.length + ' known CVEs',
      raw: {
        ports,
        vulns,
        os:        data.os,
        org:       data.org,
        isp:       data.isp,
        hostnames: data.hostnames
      },
      score: Math.min(vulns.length * 15 + ports.length * 2, 45)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Error: ' + e.message, error: e.message, score: 0 };
  }
}

async function apiHIBP(email) {
  const source = 'HaveIBeenPwned';
  const key    = localStorage.getItem('pc_key_hibp');
  if (!key) return { source, severity: 'safe', summary: 'No API key — skipped', score: 0 };

  try {
    const res = await fetch(
      'https://haveibeenpwned.com/api/v3/breachedaccount/' + encodeURIComponent(email),
      {
        headers: { 'hibp-api-key': key, 'User-Agent': 'PhantomCheck-OSINT' },
        signal:  AbortSignal.timeout(10000)
      }
    );
    if (res.status === 404) {
      return { source, severity: 'safe', summary: 'No breaches found', raw: { breaches: [] }, score: 0 };
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data     = await res.json();
    const severity = data.length >= 5 ? 'critical' : data.length > 0 ? 'warning' : 'safe';

    return {
      source,
      severity,
      summary: data.length + ' breaches found for this email',
      raw: {
        breaches: data.map(function(b) {
          return {
            name:         b.Name,
            date:         b.BreachDate,
            pwn_count:    b.PwnCount,
            data_classes: b.DataClasses
          };
        })
      },
      score: Math.min(data.length * 8, 40)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Error: ' + e.message, error: e.message, score: 0 };
  }
}

async function apiSecurityTrails(target) {
  const source = 'SecurityTrails';
  const key    = localStorage.getItem('pc_key_securitytrails');
  if (!key) return { source, severity: 'safe', summary: 'No API key — skipped', score: 0 };

  try {
    const res = await fetch(
      'https://api.securitytrails.com/v1/domain/' + encodeURIComponent(target),
      {
        headers: { 'APIKEY': key },
        signal:  AbortSignal.timeout(10000)
      }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data     = await res.json();
    const subCount = data.subdomain_count || 0;

    return {
      source,
      severity: subCount > 50 ? 'warning' : 'safe',
      summary:  subCount + ' subdomains in DNS history',
      raw: {
        hostname:       data.hostname,
        subdomain_count: subCount,
        current_dns:    data.current_dns,
        alexa_rank:     data.alexa_rank
      },
      score: Math.min(subCount, 15)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Error: ' + e.message, error: e.message, score: 0 };
  }
}

async function apiGithub(domain) {
  const source  = 'GitHub';
  const key     = localStorage.getItem('pc_key_github');
  const headers = { 'Accept': 'application/vnd.github.v3+json' };
  if (key) headers['Authorization'] = 'token ' + key;

  const queries = [
    encodeURIComponent(domain + ' password'),
    encodeURIComponent(domain + ' api_key'),
    encodeURIComponent(domain + ' secret')
  ];

  try {
    const results = await Promise.all(queries.map(function(q) {
      return fetch('https://api.github.com/search/code?q=' + q + '&per_page=5', {
        headers,
        signal: AbortSignal.timeout(10000)
      }).then(function(r) { return r.ok ? r.json() : { items: [] }; });
    }));

    const items  = results.flatMap(function(r) { return r.items || []; });
    const unique = [];
    const seen   = new Set();

    items.forEach(function(item) {
      if (!seen.has(item.html_url)) {
        seen.add(item.html_url);
        unique.push({
          repo: item.repository && item.repository.full_name,
          file: item.name,
          url:  item.html_url
        });
      }
    });

    return {
      source,
      severity: unique.length >= 3 ? 'critical' : unique.length > 0 ? 'warning' : 'safe',
      summary:  unique.length > 0
        ? unique.length + ' public files referencing ' + domain + ' found on GitHub'
        : 'No public GitHub exposure found',
      raw:   { results: unique, authenticated: !!key },
      score: Math.min(unique.length * 12, 36)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}

async function apiWhois(domain) {
  const source = 'Whois/RDAP';
  try {
    const res = await fetch(
      'https://rdap.org/domain/' + encodeURIComponent(domain),
      { signal: AbortSignal.timeout(10000) }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();

    const registrar  = (data.entities || []).find(function(e) {
      return e.roles && e.roles.includes('registrar');
    });
    const registrant = (data.entities || []).find(function(e) {
      return e.roles && e.roles.includes('registrant');
    });

    const events    = data.events || [];
    const created   = (events.find(function(e) { return e.eventAction === 'registration'; }) || {}).eventDate || null;
    const expires   = (events.find(function(e) { return e.eventAction === 'expiration'; })    || {}).eventDate || null;
    const updated   = (events.find(function(e) { return e.eventAction === 'last changed'; })  || {}).eventDate || null;

    const expirySoon = expires && (new Date(expires) - Date.now()) < 30 * 24 * 60 * 60 * 1000;
    const score      = expirySoon ? 10 : 0;

    return {
      source,
      severity: expirySoon ? 'warning' : 'safe',
      summary:  'Registered via ' +
        (registrar && registrar.vcardArray ? registrar.vcardArray[1].find(function(v) { return v[0] === 'fn'; })[3] : 'unknown registrar') +
        (expirySoon ? ' — EXPIRES SOON' : ''),
      raw: {
        registrar:       registrar ? (registrar.vcardArray || []) : null,
        registrant_org:  registrant ? (registrant.vcardArray || []) : null,
        created,
        expires,
        updated,
        status:          data.status || [],
        nameservers:     (data.nameservers || []).map(function(n) { return n.ldhName; }),
        expiry_soon:     expirySoon
      },
      score
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}

async function apiGoogleSafeBrowsing(target) {
  const source = 'Google Safe Browsing';
  const key    = localStorage.getItem('pc_key_gsb');
  if (!key) return { source, severity: 'safe', summary: 'No API key — skipped', score: 0 };

  try {
    const body = {
      client:    { clientId: 'phantomcheck', clientVersion: '1.0' },
      threatInfo: {
        threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes:    ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries:    [{ url: 'https://' + target }]
      }
    };

    const res = await fetch(
      'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + key,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
        signal:  AbortSignal.timeout(10000)
      }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data    = await res.json();
    const matches = data.matches || [];

    return {
      source,
      severity: matches.length > 0 ? 'critical' : 'safe',
      summary:  matches.length > 0
        ? matches.length + ' threat(s) flagged by Google: ' + [...new Set(matches.map(function(m) { return m.threatType; }))].join(', ')
        : 'No threats detected by Google Safe Browsing',
      raw:   { matches },
      score: matches.length * 30
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Error: ' + e.message, error: e.message, score: 0 };
  }
}

function analyzeSpfDkimDmarc(dnsRaw) {
  const source = 'SPF/DKIM/DMARC';

  if (!dnsRaw || !dnsRaw.records) {
    return { source, severity: 'safe', summary: 'DNS data unavailable — skipped', score: 0 };
  }

  const txt      = dnsRaw.records.TXT || [];
  const spf      = txt.find(function(t) { return t.includes('v=spf1'); })      || null;
  const dmarc    = txt.find(function(t) { return t.includes('v=DMARC1'); })    || null;
  const dkim     = txt.find(function(t) { return t.includes('v=DKIM1'); })     || null;

  const issues   = [];
  if (!spf)   issues.push('No SPF record — anyone can spoof email from this domain');
  if (!dmarc) issues.push('No DMARC policy — spoofed emails reach inboxes with no quarantine or reject rule');
  if (!dkim)  issues.push('No DKIM record found in TXT — email integrity cannot be verified by receivers');

  const dmarcPolicy = dmarc ? (dmarc.match(/p=([^;]+)/) || [])[1] : null;
  if (dmarcPolicy === 'none') issues.push('DMARC policy is p=none — monitoring only, no enforcement');

  const score    = issues.length * 10;
  const severity = issues.length >= 3 ? 'critical' : issues.length >= 1 ? 'warning' : 'safe';

  return {
    source,
    severity,
    summary: issues.length === 0
      ? 'SPF, DKIM and DMARC all present — email authentication looks solid'
      : issues.length + ' email authentication issue(s) found',
    raw: {
      spf_record:    spf,
      dkim_record:   dkim,
      dmarc_record:  dmarc,
      dmarc_policy:  dmarcPolicy,
      issues
    },
    score
  };
}

async function apiWayback(domain) {
  const source = 'Wayback Machine';
  try {
    const res = await fetch(
      'https://archive.org/wayback/available?url=' + encodeURIComponent(domain),
      { signal: AbortSignal.timeout(10000) }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data     = await res.json();
    const snapshot = data.archived_snapshots && data.archived_snapshots.closest;

    if (!snapshot || !snapshot.available) {
      return {
        source,
        severity: 'safe',
        summary:  'No archived snapshots found — domain may be new or never indexed',
        raw:      { available: false },
        score:    0
      };
    }

    const snapDate  = new Date(
      snapshot.timestamp.replace(
        /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/,
        '$1-$2-$3T$4:$5:$6Z'
      )
    );
    const ageYears  = (Date.now() - snapDate.getTime()) / (365.25 * 24 * 60 * 60 * 1000);
    const ageSummary = ageYears >= 1
      ? 'oldest snapshot ' + Math.floor(ageYears) + ' year(s) ago'
      : 'snapshot within the last year';

    return {
      source,
      severity: 'safe',
      summary:  'Domain has archive history — ' + ageSummary,
      raw: {
        available:       true,
        snapshot_url:    snapshot.url,
        snapshot_date:   snapshot.timestamp,
        age_years:       Math.round(ageYears * 10) / 10,
        status:          snapshot.status
      },
      score: 0
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}

async function apiIpinfo(ip) {
  const source = 'IPinfo';
  try {
    const res = await fetch(
      'https://ipinfo.io/' + encodeURIComponent(ip) + '/json',
      { signal: AbortSignal.timeout(10000) }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data    = await res.json();
    const isVpn   = data.org && (
      data.org.toLowerCase().includes('vpn')    ||
      data.org.toLowerCase().includes('proxy')  ||
      data.org.toLowerCase().includes('hosting')||
      data.org.toLowerCase().includes('cloud')
    );
    const isTor   = data.org && data.org.toLowerCase().includes('tor');
    const flags   = [];
    if (isTor) flags.push('Tor exit node detected');
    if (isVpn) flags.push('Possible VPN or hosting provider — anonymisation likely');

    return {
      source,
      severity: isTor ? 'critical' : isVpn ? 'warning' : 'safe',
      summary:  data.org + ' — ' + (data.city || '') + ', ' + (data.country || '') +
        (flags.length ? ' — ' + flags.join('; ') : ''),
      raw: {
        ip:       data.ip,
        city:     data.city,
        region:   data.region,
        country:  data.country,
        org:      data.org,
        timezone: data.timezone,
        is_vpn:   isVpn,
        is_tor:   isTor,
        hostname: data.hostname || null
      },
      score: isTor ? 30 : isVpn ? 10 : 0
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}
