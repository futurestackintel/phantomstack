async function runScan(target, type, mode) {
  scanBtnState(true);
  terminalShow();
  terminalSetCmd(target);

  const cached = cacheGet(target, type);
  if (cached) {
    terminalLog('Cache hit — loading previous result', 'success');
    await delay(600);
    presentResults(cached, target, mode);
    scanBtnState(false);
    return;
  }

  const promises = [];

  if (type === INPUT_TYPES.DOMAIN) {
    promises.push(tracked('crt.sh',               apiCrtSh(target)));
    promises.push(tracked('urlscan.io',            apiUrlscan(target)));
    promises.push(tracked('DNS Lookup',            apiDns(target)));
    promises.push(tracked('Africa Regional Check', apiAfricaCheck(target)));
    promises.push(tracked('GitHub',               apiGithub(target)));
    promises.push(tracked('VirusTotal',            apiVirusTotal(target, type)));
    promises.push(tracked('SecurityTrails',        apiSecurityTrails(target)));
  }

  if (type === INPUT_TYPES.IP) {
    promises.push(tracked('AbuseIPDB',  apiAbuseIPDB(target)));
    promises.push(tracked('VirusTotal', apiVirusTotal(target, type)));
    promises.push(tracked('Shodan',     apiShodan(target, type)));
  }

  if (type === INPUT_TYPES.EMAIL) {
    const domain = target.split('@')[1];
    promises.push(tracked('DNS Lookup',            apiDns(domain)));
    promises.push(tracked('Africa Regional Check', apiAfricaCheck(domain)));
    promises.push(tracked('HaveIBeenPwned',        apiHIBP(target)));
    promises.push(tracked('VirusTotal',            apiVirusTotal(domain, INPUT_TYPES.DOMAIN)));
  }

  const results = await Promise.all(promises);

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
  const validResults = results.filter(r => !r.error && r.severity !== undefined);
  const totalScore = Math.min(
    validResults.reduce((sum, r) => sum + (r.score || 0), 0),
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
  renderModeOutput(
    '<p style="color:var(--text-muted);font-size:0.9rem;padding:var(--space-lg)">' +
    'AI interpretation requires Claude API key. Add your key in API Keys settings to enable Explorer, Analyst and Operator mode analysis.</p>'
  );
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
