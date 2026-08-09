<div align="center">

```
 ____  _______ _   _ _____ _____ _   _ _____ _
 / ___|| ____|_| \ | |_   _|_ _| \ | | ____| |
   \___ \|  _| | .` |  | |  | ||  \| |  _| | |
     ___) | |___| |\  |  | |  | || |\  | |___| |___
     |____/|_____|_| \_|  |_| |___|_| \_|_____|_____|
```

### ✦ Domain Registration & Ownership Intelligence ✦

**Public WHOIS/DNS lookups only. No exploitation.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Made by Mindless](https://img.shields.io/badge/Made%20by-Mindless-ff69b4.svg)](https://linxploit.com/founder)
[![Linxploit](https://img.shields.io/badge/Linxploit-linxploit.com-black.svg)](https://linxploit.com)

**Made by [Mindless](https://linxploit.com/founder) — Founder & CEO of [Linxploit](https://linxploit.com)**

</div>

---

## 🧠 What is DomainSentinel?

**DomainSentinel** queries the public WHOIS registry for a domain — the same lookup performed by the `whois` command, ICANN Lookup, or any registrar's "who owns this domain" page — and turns the raw result into a clear registration timeline, ownership summary, and a set of practical risk flags.

It's built for the questions that come up constantly around domain hygiene and due diligence: *Is this domain about to expire? Is it on hold? Is it in a pending-deletion window that makes it a takeover target? Who registered it, and how recently? Does it even have DNSSEC?*

WHOIS is public registry data by design — this tool performs no authentication bypass and touches no systems beyond standard WHOIS/DNS queries.

---

## ✨ Features

- 🎨 **Clean, structured terminal report** — gradient banner, sectioned output (registration, timeline, registrant, name servers, status, risk factors), and a plain-language executive summary.
- 🧮 **Practical risk analysis**, not just a data dump:
  - **Expiry tracking** — CRITICAL if already expired or expiring within a week, HIGH within 30 days.
  - **Domain-age flags** — newly/recently registered domains flagged (a common signal in phishing infrastructure).
  - **Hold & deletion states** — `clientHold`/`serverHold` and `pendingDelete`/`redemptionPeriod` are surfaced as CRITICAL, since they often precede a domain becoming available for anyone to re-register.
  - **DNSSEC, missing name servers, missing abuse contact** — smaller but genuinely useful hygiene checks.
  - **Privacy-registrar detection** — recognizes 15+ common privacy/proxy registrar patterns and explains what a masked registrant does and doesn't mean.
- 📖 **EPP status code glossary built in** — every domain status code (`clientTransferProhibited`, `pendingDelete`, etc.) is shown with a plain-English explanation, not just the raw ICANN jargon.
- 🌐 **Optional DNS resolution** (`--resolve`) — see the domain's current A/AAAA records alongside its registration data.
- 🛡️ **Robust date handling** — normalizes both naive and timezone-aware timestamps from different registries so age/expiry math never breaks.
- ⚡ **Bulk lookups** — a single domain or an entire list, scanned concurrently (kept modest by default out of respect for WHOIS server rate limits).
- 📊 **Exportable reports** — full **JSON** (every field + risk factor) or summary **CSV**.

---

## 📸 Preview

```
✦ Domain Registration & Ownership Intelligence ✦
v1.0.0 · Public WHOIS/DNS lookups only. No exploitation.

[ DOMAIN: example.com ]
──────────────────────────────────────────────────
  Registrar          : Example Registrar Inc.
  Created            : 2016-08-11 10:28:10  (3650 days / 10.0 yrs old)
  Expires            : 2027-02-25 10:28:10  [199 days remaining]

  Name Servers
    • ns1.example.com
    • ns2.example.com

  Status Codes
    • ok  — No pending operations or restrictions.

  Risk Factors

    [INFO] No Abuse Contact Listed
      ├─ No registrar abuse contact email was found in the WHOIS response.
      └─ → Useful to know in advance if you ever need to report abuse involving this domain.

  ✔ No critical or high-risk issues detected.
```

On a domain in trouble:

```
  Expires            : 2026-08-04 10:28:17  [EXPIRED 6 days ago]

  Status Codes
    • clientHold  — Registrar has told the registry not to activate the domain in DNS — the site will not resolve.
    • pendingDelete  — Domain is in its final pre-deletion window; may become available to the public soon.

  Risk Factors

    [CRITICAL] Expired Domain
      ├─ Domain expired 6 day(s) ago.
      └─ → An expired domain can lapse into the public pool and be re-registered by anyone — high takeover risk if still linked from DNS/email records.

  ⚠ CRITICAL ISSUES DETECTED — 4 issue(s) need immediate attention.
```

---

## 📦 Installation

```bash
git clone https://github.com/linxploit/domain-sentinel.git
cd domain-sentinel
pip install -r requirements.txt
```

Requires **Python 3.8+**.

---

## 🚀 Usage

### Look up a single domain

```bash
python3 domainsentinel.py -d example.com
```

### Also resolve its current DNS records

```bash
python3 domainsentinel.py -d example.com --resolve
```

### Look up a list of domains

```bash
python3 domainsentinel.py -l examples/domains.txt --threads 3
```

### See the raw WHOIS response too

```bash
python3 domainsentinel.py -d example.com -v
```

### Save a report

```bash
python3 domainsentinel.py -l examples/domains.txt -o report.json
python3 domainsentinel.py -l examples/domains.txt -o report.csv
```

### Full option reference

```bash
python3 domainsentinel.py --help
```

| Flag | Description |
|---|---|
| `-d`, `--domain` | Domain to look up (e.g. `example.com`) |
| `-l`, `--list` | File with one domain per line |
| `-t`, `--timeout` | WHOIS/DNS timeout in seconds (default: `15`) |
| `--threads` | Concurrent domain lookups (default: `3`) |
| `--resolve` | Also resolve the domain's current DNS A/AAAA records |
| `-o`, `--output` | Save report to `.json` or `.csv` |
| `-v`, `--verbose` | Show a raw WHOIS response excerpt |
| `--no-banner` | Suppress the ASCII banner |
| `--version` | Print version info and exit |

---

## 🧭 Risk levels

| Severity | Examples |
|---|---|
| **CRITICAL** | Expired domain, expiring within 7 days, on hold, pending deletion, no name servers configured |
| **HIGH** | Expiring within 30 days, newly registered (under 30 days old) |
| **MEDIUM** | Recently registered (30–90 days old) |
| **LOW** | DNSSEC not enabled |
| **INFO** | Privacy protection enabled, redacted registrant, no abuse contact listed |

> ⚠️ **A risk flag describes registry-level facts, not an accusation.** Privacy protection and redacted registrant info are extremely common and not inherently suspicious — DomainSentinel calls them out because they're relevant context, not because they're a red flag on their own.

---

## ⚖️ A note on scope

WHOIS is a public protocol — anyone can query it for any domain, the same way anyone can visit ICANN Lookup. DomainSentinel doesn't authenticate to anything, doesn't bypass any access control, and doesn't touch any system beyond standard WHOIS and DNS queries. That said:

- Some registries rate-limit or block automated WHOIS queries — the built-in thread cap is intentionally modest.
- Respect each registry's terms of use, especially for bulk lookups.
- You are solely responsible for how you use this tool and for complying with all applicable laws and registry terms.

---

## 🛠️ Project structure

```
domain-sentinel/
├── domainsentinel.py       # Main executable — the tool itself
├── requirements.txt          # Python dependencies
├── examples/
│   └── domains.txt             # Example domain list for -l/--list
├── tests/
│   └── test_domainsentinel.py  # Unit tests (mocked WHOIS responses)
├── LICENSE                    # MIT License
└── README.md                   # You are here
```

---

## 🤝 Contributing

Issues and pull requests are welcome — additional risk heuristics, a richer EPP status glossary, and support for registry-specific WHOIS quirks are all great contributions.

---

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">

### Made by **Mindless**
**Founder & CEO of [Linxploit](https://linxploit.com)**

🌐 [linxploit.com](https://linxploit.com) &nbsp;·&nbsp; 👤 [linxploit.com/founder](https://linxploit.com/founder)

</div>
