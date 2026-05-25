async function runScan(target, type, mode) {
  scanBtnState(true);
  terminalShow();
  terminalSetCmd(target);
  clearScanChat();
  const cached = cacheGet(target, type);
  if (cached) {
    terminalLog('Cache hit — results from ' + cacheAge(cached.ts), 'success');
    await delay(600);
    presentResults(cached.data, target, mode);
    scanBtnState(false);
    return;
  }
  var results = [];
  if (type === INPUT_TYPES.DOMAIN) {
    const dnsResult = await tracked('DNS Lookup', apiDns(target));
    const wave2 = await Promise.all([
      tracked('crt.sh',               apiCrtSh(target)),
      tracked('urlscan.io',            apiUrlscan(target)),
      tracked('Africa Regional Check', apiAfricaCheck(target)),
      tracked('GitHub',                apiGithub(target)),
      tracked('VirusTotal',            apiVirusTotal(target, type)),
      tracked('SecurityTrails',        apiSecurityTrails(target)),
      tracked('Whois/RDAP',            apiWhois(target)),
      tracked('Google Safe Browsing',  apiGoogleSafeBrowsing(target)),
      tracked('Wayback Machine',       apiWayback(target)),
      tracked('SPF/DKIM/DMARC',        Promise.resolve(analyzeSpfDkimDmarc(dnsResult.raw)))
    ]);
    results = [dnsResult].concat(wave2);
  }
  if (type === INPUT_TYPES.IP) {
    const wave = await Promise.all([
      tracked('AbuseIPDB',   apiAbuseIPDB(target)),
      tracked('VirusTotal',  apiVirusTotal(target, type)),
      tracked('Shodan',      apiShodan(target, type)),
      tracked('IPinfo',      apiIpinfo(target))
    ]);
    results = wave;
  }
  if (type === INPUT_TYPES.EMAIL) {
    const domain = target.split('@')[1];
    const dnsResult = await tracked('DNS Lookup', apiDns(domain));
    const wave2 = await Promise.all([
      tracked('Africa Regional Check', apiAfricaCheck(domain)),
      tracked('HaveIBeenPwned',        apiHIBP(target)),
      tracked('VirusTotal',            apiVirusTotal(domain, INPUT_TYPES.DOMAIN)),
      tracked('Whois/RDAP',            apiWhois(domain)),
      tracked('Google Safe Browsing',  apiGoogleSafeBrowsing(domain)),
      tracked('Wayback Machine',       apiWayback(domain)),
      tracked('SPF/DKIM/DMARC',        Promise.resolve(analyzeSpfDkimDmarc(dnsResult.raw)))
    ]);
    results = [dnsResult].concat(wave2);
  }
  cacheSet(target, type, results);
  presentResults(results, target, mode);
  scanBtnState(false);
}

async function tracked(label, promise) {
  terminalLog('Querying ' + label + '...', 'checking');
  const result = await promise;
  const status = result.error ? 'error'
    : result.severity === 'critical' ? 'warning'
    : 'success';
  terminalLog(label + ' — ' + result.summary, status);
  return result;
}

function presentResults(results, target, mode) {
  const validResults = results.filter(function(r) {
    return !r.error && r.severity !== undefined;
  });
  const totalScore = Math.min(
    validResults.reduce(function(sum, r) { return sum + (r.score || 0); }, 0),
    100
  );
  const description = totalScore >= 70
    ? 'Significant exposure detected. Review findings below.'
    : totalScore >= 40
    ? 'Moderate exposure detected. Some items need attention.'
    : 'Low exposure detected. No critical findings.';
  terminalDone();
  gaugeAnimate(totalScore);
  setRiskMeta(target, description);
  renderApiCards(results);
  runAI(results, detectInputType(target), target, mode)
    .then(function() {
      initScanChat(results, detectInputType(target), target, mode);
    });
}

function delay(ms) {
  return new Promise(function(resolve) { setTimeout(resolve, ms); });
}
