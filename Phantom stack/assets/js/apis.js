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
      data.map(e => e.name_value)
           .join('\n')
           .split('\n')
           .map(s => s.trim().toLowerCase())
           .filter(s => s && !s.startsWith('*'))
    )].slice(0, 50);

    return {
      source,
      severity: names.length > 10 ? 'warning' : 'safe',
      summary: names.length + ' subdomains found via certificate transparency',
      raw: { subdomains: names, total_certs: data.length },
      score: Math.min(names.length * 2, 20)
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
    const data = await res.json();
    const results = data.results || [];

    const malicious = results.filter(r => r.verdicts && r.verdicts.overall &&
      r.verdicts.overall.malicious).length;

    const severity = malicious > 0 ? 'critical' : results.length > 0 ? 'safe' : 'safe';

    return {
      source,
      severity,
      summary: results.length + ' scans found' +
        (malicious > 0 ? ', ' + malicious + ' flagged malicious' : ''),
      raw: results.map(r => ({
        url: r.page && r.page.url,
        ip: r.page && r.page.ip,
        country: r.page && r.page.country,
        malicious: r.verdicts && r.verdicts.overall && r.verdicts.overall.malicious,
        scanned: r.task && r.task.time
      })),
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
        headers: { 'Key': 'demo', 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000)
      }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const d = data.data || {};

    const score = d.abuseConfidenceScore || 0;
    const severity = score >= 80 ? 'critical' : score >= 30 ? 'warning' : 'safe';

    return {
      source,
      severity,
      summary: 'Abuse confidence: ' + score + '% — ' +
        (d.totalReports || 0) + ' reports in 90 days',
      raw: {
        ip: d.ipAddress,
        abuse_score: score,
        total_reports: d.totalReports,
        country: d.countryCode,
        isp: d.isp,
        usage_type: d.usageType,
        is_tor: d.isTor,
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
    const types = ['A', 'MX', 'TXT', 'NS', 'AAAA'];
    const records = {};

    await Promise.all(types.map(async function(type) {
      const res = await fetch(
        'https://dns.google/resolve?name=' + encodeURIComponent(target) +
          '&type=' + type,
        { signal: AbortSignal.timeout(8000) }
      );
      if (!res.ok) return;
      const data = await res.json();
      if (data.Answer && data.Answer.length) {
        records[type] = data.Answer.map(a => a.data);
      }
    }));

    const hasMx  = !!records.MX;
    const hasTxt = !!records.TXT;
    const spf    = hasTxt && records.TXT.some(t => t.includes('v=spf1'));
    const dmarc  = hasTxt && records.TXT.some(t => t.includes('v=DMARC1'));

    const issues = [];
    if (!spf)   issues.push('No SPF record — domain spoofable for email phishing');
    if (!dmarc) issues.push('No DMARC record — no email authentication policy');

    return {
      source,
      severity: issues.length >= 2 ? 'warning' : 'safe',
      summary: Object.keys(records).join(', ') + ' records found' +
        (issues.length ? ' — ' + issues.length + ' email security gaps' : ''),
      raw: { records, issues },
      score: issues.length * 8
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}

async function apiAfricaCheck(target) {
  const source = 'Africa Regional Check';
  const isNg = target.endsWith('.ng') || target.endsWith('.com.ng');
  const isZa = target.endsWith('.co.za') || target.endsWith('.za');

  const findings = [];
  let score = 0;

  if (isNg) findings.push('Nigerian domain (.ng) — checking regional exposure');
  if (isZa) findings.push('South African domain (.za) — checking regional exposure');

  try {
    const whoisRes = await fetch(
      'https://dns.google/resolve?name=' + encodeURIComponent(target) + '&type=A',
      { signal: AbortSignal.timeout(8000) }
    );
    const whoisData = await whoisRes.json();
    const ips = whoisData.Answer ? whoisData.Answer.map(a => a.data) : [];

    if (ips.length) findings.push('Resolves to: ' + ips.join(', '));

    const africanRanges = ['41.', '102.', '105.', '196.', '197.', '154.'];
    const africanIp = ips.some(ip => africanRanges.some(r => ip.startsWith(r)));

    if (africanIp) {
      findings.push('Hosted on African IP range — verify datacenter security posture');
      score += 5;
    }

    if (isNg || isZa) score += 5;

    return {
      source,
      severity: score > 5 ? 'warning' : 'safe',
      summary: (isNg || isZa)
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
  const key = localStorage.getItem('pc_key_virustotal');
  if (!key) return { source, severity: 'safe', summary: 'No API key — skipped', score: 0 };

  const endpoint = type === INPUT_TYPES.IP
    ? 'https://www.virustotal.com/api/v3/ip_addresses/' + encodeURIComponent(target)
    : 'https://www.virustotal.com/api/v3/domains/' + encodeURIComponent(target);

  try {
    const res = await fetch(endpoint, {
      headers: { 'x-apikey': key },
      signal: AbortSignal.timeout(10000)
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const stats = data.data &&
      data.data.attributes &&
      data.data.attributes.last_analysis_stats || {};

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const severity = malicious > 3 ? 'critical' : malicious > 0 || suspicious > 0 ? 'warning' : 'safe';

    return {
      source,
      severity,
      summary: malicious + ' malicious · ' + suspicious + ' suspicious out of ' +
        ((stats.harmless || 0) + malicious + suspicious + (stats.undetected || 0)) + ' vendors',
      raw: { stats, reputation: data.data && data.data.attributes && data.data.attributes.reputation },
      score: Math.min(malicious * 8 + suspicious * 3, 40)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Error: ' + e.message, error: e.message, score: 0 };
  }
}

async function apiShodan(target, type) {
  const source = 'Shodan';
  const key = localStorage.getItem('pc_key_shodan');
  if (!key) return { source, severity: 'safe', summary: 'No API key — skipped', score: 0 };

  const endpoint = type === INPUT_TYPES.IP
    ? 'https://api.shodan.io/shodan/host/' + encodeURIComponent(target) + '?key=' + key
    : 'https://api.shodan.io/dns/resolve?hostnames=' + encodeURIComponent(target) + '&key=' + key;

  try {
    const res = await fetch(endpoint, { signal: AbortSignal.timeout(12000) });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();

    const ports = data.ports || [];
    const vulns = data.vulns ? Object.keys(data.vulns) : [];
    const severity = vulns.length > 0 ? 'critical' : ports.length > 5 ? 'warning' : 'safe';

    return {
      source,
      severity,
      summary: ports.length + ' open ports · ' + vulns.length + ' known CVEs',
      raw: {
        ports,
        vulns,
        os: data.os,
        org: data.org,
        isp: data.isp,
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
  const key = localStorage.getItem('pc_key_hibp');
  if (!key) return { source, severity: 'safe', summary: 'No API key — skipped', score: 0 };

  try {
    const res = await fetch(
      'https://haveibeenpwned.com/api/v3/breachedaccount/' + encodeURIComponent(email),
      {
        headers: { 'hibp-api-key': key, 'User-Agent': 'PhantomCheck-OSINT' },
        signal: AbortSignal.timeout(10000)
      }
    );
    if (res.status === 404) {
      return { source, severity: 'safe', summary: 'No breaches found', raw: { breaches: [] }, score: 0 };
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();

    const severity = data.length >= 5 ? 'critical' : data.length > 0 ? 'warning' : 'safe';

    return {
      source,
      severity,
      summary: data.length + ' breaches found for this email',
      raw: {
        breaches: data.map(b => ({
          name: b.Name,
          date: b.BreachDate,
          pwn_count: b.PwnCount,
          data_classes: b.DataClasses
        }))
      },
      score: Math.min(data.length * 8, 40)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Error: ' + e.message, error: e.message, score: 0 };
  }
}

async function apiSecurityTrails(target) {
  const source = 'SecurityTrails';
  const key = localStorage.getItem('pc_key_securitytrails');
  if (!key) return { source, severity: 'safe', summary: 'No API key — skipped', score: 0 };

  try {
    const res = await fetch(
      'https://api.securitytrails.com/v1/domain/' + encodeURIComponent(target),
      {
        headers: { 'APIKEY': key },
        signal: AbortSignal.timeout(10000)
      }
    );
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();

    const subCount = data.subdomain_count || 0;
    const severity = subCount > 50 ? 'warning' : 'safe';

    return {
      source,
      severity,
      summary: subCount + ' subdomains in DNS history',
      raw: {
        hostname: data.hostname,
        subdomain_count: subCount,
        current_dns: data.current_dns,
        alexa_rank: data.alexa_rank
      },
      score: Math.min(subCount, 15)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Error: ' + e.message, error: e.message, score: 0 };
  }
}
async function apiGithub(domain) {
  const source = 'GitHub';
  const key = localStorage.getItem('pc_key_github');

  const headers = { 'Accept': 'application/vnd.github.v3+json' };
  if (key) headers['Authorization'] = 'token ' + key;

  const queries = [
    encodeURIComponent(domain + ' password'),
    encodeURIComponent(domain + ' api_key'),
    encodeURIComponent(domain + ' secret')
  ];

  try {
    const results = await Promise.all(queries.map(q =>
      fetch('https://api.github.com/search/code?q=' + q + '&per_page=5', {
        headers,
        signal: AbortSignal.timeout(10000)
      }).then(r => r.ok ? r.json() : { items: [] })
    ));

    const items = results.flatMap(r => r.items || []);
    const unique = [];
    const seen = new Set();

    items.forEach(function(item) {
      if (!seen.has(item.html_url)) {
        seen.add(item.html_url);
        unique.push({
          repo: item.repository && item.repository.full_name,
          file: item.name,
          url: item.html_url,
          query: item.name
        });
      }
    });

    const severity = unique.length >= 3 ? 'critical'
      : unique.length > 0 ? 'warning'
      : 'safe';

    return {
      source,
      severity,
      summary: unique.length > 0
        ? unique.length + ' public files referencing ' + domain + ' found on GitHub'
        : 'No public GitHub exposure found',
      raw: { results: unique, authenticated: !!key },
      score: Math.min(unique.length * 12, 36)
    };
  } catch (e) {
    return { source, severity: 'safe', summary: 'Unavailable', error: e.message, score: 0 };
  }
}
