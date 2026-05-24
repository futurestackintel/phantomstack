# PhantomCheck
> AI-powered OSINT reconnaissance tool. Free. Browser-based. BYOK. Three modes: Explorer, Analyst, Operator.

**Status: Live — [Launch App](https://phantomstack.pages.dev/app.html) · [Join the Waitlist](https://phantomstack.pages.dev/)**

Built by [FutureStack Intelligence](https://github.com/futurestackintel) · Ilorin, Nigeria

---

## Live URLs
| | |
|---|---|
| App | https://phantomstack.pages.dev/app.html |
| Waitlist | https://phantomstack.pages.dev/ |

---

## What PhantomCheck Does
PhantomCheck scans any domain, email address, IP or company name against multiple security APIs simultaneously — then uses Claude AI to interpret the results in three completely different ways:

- **Explorer Mode** — Plain English. Zero jargon. For regular people and business owners.
- **Analyst Mode** — Structured professional security report. For IT managers and founders.
- **Operator Mode** — Raw technical data with CVE references. For penetration testers and researchers.

---

## Supported Targets
- Domain names (e.g. `example.com`)
- Email addresses (e.g. `user@example.com`)
- IP addresses (e.g. `192.168.1.1`)
- Company names (e.g. `Acme Corp`)

---

## How to Use
1. Open the app at `https://phantomstack.pages.dev/app.html`
2. Click the settings icon and paste in your API keys
3. Enter a domain, email, IP or company name
4. Select a mode — Explorer, Analyst or Operator
5. Hit Scan

**Claude API key is required.** All other keys are optional but unlock more data.

---

## API Keys

### Free — No Key Needed
| API | What It Checks |
|-----|---------------|
| crt.sh | SSL certificate history |
| urlscan.io | URL and page scan history |
| AbuseIPDB | IP abuse reports |
| DNS Lookup | DNS records |
| Africa Regional Check | .ng and .za domain intelligence |

### BYOK — Bring Your Own Key
| API | What It Checks | Get Key |
|-----|---------------|---------|
| Claude AI | Interprets all results, generates report | [console.anthropic.com](https://console.anthropic.com) |
| VirusTotal | Malware and threat detection | [virustotal.com](https://virustotal.com) |
| Shodan | Open ports and exposed services | [shodan.io](https://shodan.io) |
| HaveIBeenPwned | Email breach history | [haveibeenpwned.com](https://haveibeenpwned.com) |
| SecurityTrails | DNS and domain history | [securitytrails.com](https://securitytrails.com) |
| GitHub | Code exposure and repo leaks | [github.com/settings/tokens](https://github.com/settings/tokens) |

---

## Privacy
- All API keys are stored in your browser's localStorage only
- No backend. No database. No accounts.
- Your keys and scan data never touch our servers
- All API calls go directly from your browser to the respective APIs

---

## Tech Stack
- HTML5 / CSS3 / Vanilla JavaScript — zero frameworks
- Claude AI (Anthropic) — three-mode report generation
- Cloudflare Pages — hosting and deployment
- MIT License

---

## Build Status
| Module | Status |
|--------|--------|
| 1 — Foundation and Waitlist | ✅ Complete |
| 2 — Core Interface | ✅ Complete |
| 3 — Input Validation and Rate Limiting | ✅ Complete |
| 4 — API Integration Layer | ✅ Complete |
| 5 — Free APIs | ✅ Complete |
| 6 — BYOK Premium APIs | ✅ Complete |
| 7 — AI Report Generation | ✅ Complete |
| 8 — Three Output Modes | ✅ Complete |
| 9 — Export and Share | ✅ Complete |
| 10 — Caching and Performance | ✅ Complete |

---

## V2 Roadmap
- Cloudflare Workers backend
- Server-side API key storage
- Server-side rate limiting by IP
- Frictionless Explorer experience — no key needed
- Person name search
- Scan history
- Team accounts

---

## License
This project is licensed under the [MIT License](LICENSE).

---

*Built under [FutureStack Intelligence](https://github.com/futurestackintel) — a cybersecurity and AI company based in Ilorin, Nigeria.*
