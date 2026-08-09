#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 ____  _______ _   _ _____ _____ _   _ _____ _
/ ___|| ____|_| \\ | |_   _|_ _| \\ | | ____| |
\\___ \\|  _| | .` |  | |  | ||  \\| |  _| | |
 ___) | |___| |\\  |  | |  | || |\\  | |___| |___
|____/|_____|_| \\_|  |_| |___|_| \\_|_____|_____|

DomainSentinel — Domain Registration & Ownership Intelligence
Made by Mindless — Founder & CEO of Linxploit
https://linxploit.com | https://linxploit.com/founder

WHAT THIS TOOL DOES:
    DomainSentinel queries the public WHOIS protocol for a domain — the
    exact same public registry lookup performed by the `whois` command,
    ICANN Lookup, or any registrar's "who owns this domain" page — and
    turns the result into a structured registration timeline, ownership
    summary, and a set of practical risk flags (imminent expiry, domain
    hold/redemption status, missing DNSSEC, privacy-masked ownership,
    and more). Optionally resolves the domain's current DNS records.

    WHOIS data is public registry information by design; this tool
    performs no authentication bypass, no exploitation, and touches no
    systems beyond standard WHOIS/DNS queries. Some registries rate-limit
    or block WHOIS queries — respect their terms of use.
"""

import argparse
import concurrent.futures
import csv
import json
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

import whois
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

TOOL_NAME = "DomainSentinel"
VERSION = "1.0.0"
AUTHOR = "Mindless"
ORG = "Linxploit"
SITE = "https://linxploit.com"
PORTFOLIO = "https://linxploit.com/founder"

# --------------------------------------------------------------------------- #
#  UI toolkit
# --------------------------------------------------------------------------- #

GRADIENT = [
    "\033[38;5;24m", "\033[38;5;30m", "\033[38;5;36m", "\033[38;5;37m",
    "\033[38;5;43m", "\033[38;5;49m", "\033[38;5;50m", "\033[38;5;51m",
    "\033[38;5;45m", "\033[38;5;39m",
]
RESET = Style.RESET_ALL
DIM = Style.DIM
BOLD = Style.BRIGHT

C_OK = Fore.GREEN + BOLD
C_INFO_SEV = Fore.GREEN
C_LOW = Fore.CYAN + BOLD
C_MED = Fore.YELLOW + BOLD
C_HIGH = "\033[38;5;208m" + BOLD
C_CRIT = "\033[38;5;196m" + BOLD
C_MUTE = Fore.WHITE + DIM
C_ACC = "\033[38;5;44m" + BOLD  # teal accent
C_INFO = Fore.CYAN

SEVERITY_COLOR = {
    "CRITICAL": C_CRIT, "HIGH": C_HIGH, "MEDIUM": C_MED, "LOW": C_LOW, "INFO": C_INFO_SEV,
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


UNICODE_OK = supports_unicode()

BOX = {
    "tl": "╔" if UNICODE_OK else "+", "tr": "╗" if UNICODE_OK else "+",
    "bl": "╚" if UNICODE_OK else "+", "br": "╝" if UNICODE_OK else "+",
    "h": "═" if UNICODE_OK else "-", "v": "║" if UNICODE_OK else "|",
    "lt": "╠" if UNICODE_OK else "+", "rt": "╣" if UNICODE_OK else "+",
    "thin": "─" if UNICODE_OK else "-",
    "check": "✔" if UNICODE_OK else "OK", "cross": "✘" if UNICODE_OK else "X",
    "warn": "⚠" if UNICODE_OK else "!", "spark": "✦" if UNICODE_OK else "*",
    "globe": "🌐" if UNICODE_OK else "[W]", "dot": "•" if UNICODE_OK else "*",
    "arrow": "→" if UNICODE_OK else "->", "tree": "├─" if UNICODE_OK else "|-",
    "treeend": "└─" if UNICODE_OK else "`-",
}

BANNER_ART = r"""
 ____  _______ _   _ _____ _____ _   _ _____ _
/ ___|| ____|_| \ | |_   _|_ _| \ | | ____| |
\___ \|  _| | .` |  | |  | ||  \| |  _| | |
 ___) | |___| |\  |  | |  | || |\  | |___| |___
|____/|_____|_| \_|  |_| |___|_| \_|_____|_____|
""".rstrip("\n")

BANNER_ART_ASCII = r"""
 ____ ____ _  _ ___ _ _  _ ____ _
/ ___| _ \| \| |_ _|| |\ | ___|| |
\___ \  __/| .  || || | . |_|  | |___
|____/|_|  |_|\_||_||_|\_|____||_____|
""".rstrip("\n")

import re as _re  # noqa: E402
ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def gradient_line(text: str) -> str:
    out = []
    n = max(len(GRADIENT) - 1, 1)
    for i, ch in enumerate(text):
        color = GRADIENT[int((i / max(len(text) - 1, 1)) * n)]
        out.append(color + ch)
    return "".join(out) + RESET


def render_banner():
    art = BANNER_ART if UNICODE_OK else BANNER_ART_ASCII
    width = max(len(strip_ansi(line)) for line in art.splitlines()) + 6

    print()
    for line in art.splitlines():
        print(gradient_line(line))
    print()

    tagline = f"{BOX['spark']} Domain Registration & Ownership Intelligence {BOX['spark']}"
    print(C_ACC + tagline.center(width) + RESET)
    sub = f"v{VERSION} · Public WHOIS/DNS lookups only. No exploitation."
    print(C_MUTE + sub.center(width) + RESET)
    print()
    info_box(
        [
            f"{BOX['dot']} Author   : {AUTHOR}  ({ORG} — Founder & CEO)",
            f"{BOX['dot']} Website  : {SITE}",
            f"{BOX['dot']} Portfolio: {PORTFOLIO}",
        ],
        title="ABOUT",
        color=Fore.MAGENTA,
    )


def info_box(lines: List[str], title: str = "", color: str = Fore.CYAN, width: Optional[int] = None):
    content_width = width or (max((len(strip_ansi(l)) for l in lines), default=20) + 4)
    top = f"{color}{BOX['tl']}{BOX['h'] * content_width}{BOX['tr']}{RESET}"
    bot = f"{color}{BOX['bl']}{BOX['h'] * content_width}{BOX['br']}{RESET}"
    print(top)
    if title:
        pad = content_width - len(title) - 2
        left = pad // 2
        right = pad - left
        print(f"{color}{BOX['v']}{RESET} {' ' * left}{BOLD}{title}{RESET}{' ' * right} {color}{BOX['v']}{RESET}")
        print(f"{color}{BOX['lt']}{BOX['h'] * content_width}{BOX['rt']}{RESET}")
    for line in lines:
        pad = max(content_width - len(strip_ansi(line)) - 1, 0)
        print(f"{color}{BOX['v']}{RESET} {Fore.WHITE}{line}{RESET}{' ' * pad}{color}{BOX['v']}{RESET}")
    print(bot)


def section(title: str, color: str = Fore.CYAN):
    print(f"\n{color}[ {title} ]{RESET}")
    print(color + BOX["thin"] * 50 + RESET)


def hr(color=C_MUTE, width=70):
    print(color + BOX["h"] * width + RESET)


# --------------------------------------------------------------------------- #
#  Knowledge base
# --------------------------------------------------------------------------- #

PRIVACY_REGISTRAR_PATTERNS = [
    "whoisguard", "domainsbyproxy", "perfect privacy", "privacyprotect",
    "privacy service", "whois privacy", "gdpr masked", "redacted for privacy",
    "contact via", "whoisagent", "anonymize", "knock knock whois not there",
    "whoisprotection", "idprotect", "privacyprotect.org", "whoisprivacyprotect",
    "identity protect", "private by design", "withheldforprivacy",
]

EPP_STATUS_GLOSSARY = {
    "ok": "No pending operations or restrictions.",
    "clienttransferprohibited": "Registrar-set lock preventing transfer to another registrar.",
    "servertransferprohibited": "Registry-set lock preventing transfer to another registrar.",
    "clientdeleteprohibited": "Registrar-set lock preventing deletion.",
    "serverdeleteprohibited": "Registry-set lock preventing deletion.",
    "clientupdateprohibited": "Registrar-set lock preventing changes to domain records.",
    "serverupdateprohibited": "Registry-set lock preventing changes to domain records.",
    "clienthold": "Registrar has told the registry not to activate the domain in DNS — the site will not resolve.",
    "serverhold": "Registry has suspended the domain — the site will not resolve.",
    "pendingdelete": "Domain is in its final pre-deletion window; may become available to the public soon.",
    "redemptionperiod": "Domain was deleted and is in a grace period where the original owner can still restore it.",
    "pendingtransfer": "A transfer to another registrar is in progress.",
    "pendingupdate": "An update to domain records is in progress.",
    "pendingcreate": "Domain registration is currently being processed.",
    "pendingrenew": "A renewal is currently being processed.",
    "autorenewperiod": "Domain recently auto-renewed and is within the grace period to reverse that renewal.",
    "inactive": "Domain has no associated name servers.",
    "addperiod": "Domain was newly registered within the last few days (add grace period).",
    "renewperiod": "Domain was recently renewed, within the renewal grace period.",
    "transferperiod": "Domain was recently transferred, within the transfer grace period.",
}

EXPIRY_CRITICAL_DAYS = 7
EXPIRY_HIGH_DAYS = 30
NEW_DOMAIN_HIGH_DAYS = 30
NEW_DOMAIN_MEDIUM_DAYS = 90


# --------------------------------------------------------------------------- #
#  Data model
# --------------------------------------------------------------------------- #

@dataclass
class RiskFactor:
    factor: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    details: str
    recommendation: str


@dataclass
class DomainRecord:
    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    registrar_url: Optional[str] = None
    registrar_iana_id: Optional[str] = None
    registrar_abuse_contact: Optional[str] = None
    registrant_name: Optional[str] = None
    registrant_organization: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_phone: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_city: Optional[str] = None
    registrant_state: Optional[str] = None
    registrant_postal: Optional[str] = None
    registrant_address: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    whois_server: Optional[str] = None


@dataclass
class ScanResult:
    domain: str
    record: Optional[DomainRecord] = None
    risk_factors: List[RiskFactor] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)
    raw_whois_snippet: Optional[str] = None
    duration_s: float = 0.0
    error: Optional[str] = None

    @property
    def worst_severity(self) -> str:
        if self.error:
            return "ERROR"
        if not self.risk_factors:
            return "INFO"
        return min(self.risk_factors, key=lambda r: SEVERITY_ORDER.get(r.severity, 5)).severity


# --------------------------------------------------------------------------- #
#  Domain normalization / parsing
# --------------------------------------------------------------------------- #

def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    d = re.sub(r"^www\.", "", d)
    return d


def _first(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _as_list(value) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    return [str(value)]


def _as_datetime(value) -> Optional[datetime]:
    value = _first(value)
    if value is None:
        return None
    if isinstance(value, datetime):
        # Normalize to naive UTC so all downstream arithmetic is safe,
        # regardless of whether the registry returned a tz-aware timestamp.
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value)[:19], fmt)
        except ValueError:
            continue
    return None


def parse_whois_result(w) -> DomainRecord:
    return DomainRecord(
        domain_name=_first(getattr(w, "domain_name", None)),
        registrar=_first(getattr(w, "registrar", None)),
        registrar_url=_first(getattr(w, "registrar_url", None)),
        registrar_iana_id=_first(getattr(w, "registrar_iana_id", None)),
        registrar_abuse_contact=_first(getattr(w, "registrar_abuse_contact_email", None)),
        registrant_name=_first(getattr(w, "name", None)),
        registrant_organization=_first(getattr(w, "org", None)),
        registrant_email=_first(getattr(w, "email", None)),
        registrant_phone=_first(getattr(w, "phone", None)),
        registrant_country=_first(getattr(w, "country", None)),
        registrant_city=_first(getattr(w, "city", None)),
        registrant_state=_first(getattr(w, "state", None)),
        registrant_postal=_first(getattr(w, "zipcode", None)),
        registrant_address=_first(getattr(w, "address", None)),
        creation_date=_as_datetime(getattr(w, "creation_date", None)),
        expiration_date=_as_datetime(getattr(w, "expiration_date", None)),
        updated_date=_as_datetime(getattr(w, "updated_date", None)),
        name_servers=sorted(set(_as_list(getattr(w, "name_servers", None)))),
        status=_as_list(getattr(w, "status", None)),
        dnssec=_first(getattr(w, "dnssec", None)),
        whois_server=_first(getattr(w, "whois_server", None)),
    )


# --------------------------------------------------------------------------- #
#  Risk analysis
# --------------------------------------------------------------------------- #

def analyze_risk(record: DomainRecord) -> List[RiskFactor]:
    risks: List[RiskFactor] = []
    now = datetime.now()

    if record.creation_date:
        age_days = (now - record.creation_date).days
        if age_days < 0:
            pass  # clock skew / bad data — skip rather than report a nonsensical negative age
        elif age_days < NEW_DOMAIN_HIGH_DAYS:
            risks.append(RiskFactor(
                "Newly Registered Domain", "HIGH",
                f"Domain was registered {age_days} day(s) ago.",
                "Newly registered domains are disproportionately used for phishing and abuse — verify legitimacy before trusting.",
            ))
        elif age_days < NEW_DOMAIN_MEDIUM_DAYS:
            risks.append(RiskFactor(
                "Recently Registered Domain", "MEDIUM",
                f"Domain was registered {age_days} day(s) ago.",
                "Still within its first few months — reasonable to double-check legitimacy.",
            ))

    if record.expiration_date:
        days_left = (record.expiration_date - now).days
        if days_left < 0:
            risks.append(RiskFactor(
                "Expired Domain", "CRITICAL",
                f"Domain expired {abs(days_left)} day(s) ago.",
                "An expired domain can lapse into the public pool and be re-registered by anyone — high takeover risk if still linked from DNS/email records.",
            ))
        elif days_left < EXPIRY_CRITICAL_DAYS:
            risks.append(RiskFactor(
                "Expiring Imminently", "CRITICAL",
                f"Domain expires in {days_left} day(s).",
                "Renew immediately to avoid service disruption or takeover risk.",
            ))
        elif days_left < EXPIRY_HIGH_DAYS:
            risks.append(RiskFactor(
                "Expiring Soon", "HIGH",
                f"Domain expires in {days_left} day(s).",
                "Schedule a renewal well before the deadline.",
            ))

    status_lower = [s.lower() for s in record.status]
    if any("hold" in s for s in status_lower):
        risks.append(RiskFactor(
            "Domain On Hold", "CRITICAL",
            "A clientHold/serverHold status is set — the domain will not resolve in DNS.",
            "Contact the registrar/registry immediately; this typically indicates suspension or a billing/compliance issue.",
        ))
    if any("pendingdelete" in s or "redemptionperiod" in s for s in status_lower):
        risks.append(RiskFactor(
            "Domain Pending Deletion", "CRITICAL",
            "The domain is in a pre-deletion or redemption grace period.",
            "If this domain matters to you, act immediately — it may become available for anyone to register soon.",
        ))

    if record.registrar:
        registrar_lower = record.registrar.lower()
        if any(p in registrar_lower for p in PRIVACY_REGISTRAR_PATTERNS):
            risks.append(RiskFactor(
                "Privacy Protection Enabled", "INFO",
                f"Registrar/registrant uses privacy protection ('{record.registrar}').",
                "Owner identity is intentionally masked — normal and common, not inherently suspicious.",
            ))

    if not record.registrant_name and not record.registrant_organization:
        risks.append(RiskFactor(
            "Redacted Registrant", "INFO",
            "Registrant name/organization is redacted or unavailable in the WHOIS response.",
            "Common due to GDPR/registrar privacy defaults — not inherently suspicious on its own.",
        ))

    if not record.dnssec or str(record.dnssec).lower() in ("unsigned", "none", "no"):
        risks.append(RiskFactor(
            "DNSSEC Not Enabled", "LOW",
            "The domain does not appear to have DNSSEC enabled at the registry.",
            "DNSSEC helps prevent DNS spoofing/cache-poisoning attacks — consider enabling it if the registrar supports it.",
        ))

    if not record.name_servers:
        risks.append(RiskFactor(
            "No Name Servers", "CRITICAL",
            "No name servers are configured for this domain.",
            "The domain will not resolve — may be inactive, newly registered and not yet configured, or misconfigured.",
        ))

    if not record.registrar_abuse_contact:
        risks.append(RiskFactor(
            "No Abuse Contact Listed", "INFO",
            "No registrar abuse contact email was found in the WHOIS response.",
            "Useful to know in advance if you ever need to report abuse involving this domain.",
        ))

    return risks


def resolve_dns(domain: str, timeout: int = 5) -> List[str]:
    ips = set()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            ips.add(info[4][0])
    except Exception:
        pass
    return sorted(ips)


# --------------------------------------------------------------------------- #
#  Core scan
# --------------------------------------------------------------------------- #

def scan_domain(domain: str, timeout: int, resolve: bool, snippet_len: int = 2000) -> ScanResult:
    domain = normalize_domain(domain)
    result = ScanResult(domain=domain)
    start = time.perf_counter()

    try:
        socket.setdefaulttimeout(timeout)
        w = whois.whois(domain)
        record = parse_whois_result(w)
        result.record = record
        result.risk_factors = analyze_risk(record)
        raw_text = getattr(w, "text", None) or str(w)
        result.raw_whois_snippet = raw_text[:snippet_len] if raw_text else None
    except Exception as e:  # noqa
        result.error = str(e) or e.__class__.__name__

    if resolve:
        result.resolved_ips = resolve_dns(domain, timeout)

    result.duration_s = round(time.perf_counter() - start, 2)
    return result


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #

def format_date(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(dt, datetime) else "—"


def print_result(result: ScanResult, verbose: bool):
    section(f"DOMAIN: {result.domain}", Fore.CYAN)

    if result.error:
        print(f"  {C_CRIT}{BOX['cross']} WHOIS lookup failed: {result.error}{RESET}")
        print(f"  {C_MUTE}This can happen for rate-limited registries, unsupported TLDs, "
              f"or registries that require a different WHOIS server.{RESET}")
        return

    record = result.record
    print(f"  {C_MUTE}Lookup time: {result.duration_s}s{RESET}")

    # --- Registration ---
    print(f"\n  {C_ACC}Registrar{RESET}          : {record.registrar or '—'}")
    if record.registrar_iana_id:
        print(f"  {C_ACC}IANA ID{RESET}            : {record.registrar_iana_id}")
    if record.whois_server:
        print(f"  {C_ACC}WHOIS Server{RESET}       : {record.whois_server}")

    # --- Timeline ---
    print(f"\n  {C_ACC}Created{RESET}            : {format_date(record.creation_date)}", end="")
    if record.creation_date:
        age_days = (datetime.now() - record.creation_date).days
        print(f"  {C_MUTE}({age_days} days / {age_days / 365:.1f} yrs old){RESET}")
    else:
        print()

    if record.expiration_date:
        days_left = (record.expiration_date - datetime.now()).days
        if days_left < 0:
            exp_color, exp_label = C_CRIT, f"EXPIRED {abs(days_left)} days ago"
        elif days_left < EXPIRY_CRITICAL_DAYS:
            exp_color, exp_label = C_CRIT, f"expires in {days_left} days"
        elif days_left < EXPIRY_HIGH_DAYS:
            exp_color, exp_label = C_HIGH, f"expires in {days_left} days"
        elif days_left < 90:
            exp_color, exp_label = C_MED, f"expires in {days_left} days"
        else:
            exp_color, exp_label = C_OK, f"{days_left} days remaining"
        print(f"  {C_ACC}Expires{RESET}            : {format_date(record.expiration_date)}  "
              f"{exp_color}[{exp_label}]{RESET}")
    if record.updated_date:
        print(f"  {C_ACC}Last Updated{RESET}       : {format_date(record.updated_date)}")

    # --- Registrant ---
    reg_fields = [
        ("Name", record.registrant_name), ("Organization", record.registrant_organization),
        ("Email", record.registrant_email), ("Phone", record.registrant_phone),
        ("Country", record.registrant_country), ("City", record.registrant_city),
        ("State", record.registrant_state), ("Postal", record.registrant_postal),
    ]
    has_registrant = any(v for _, v in reg_fields)
    if has_registrant:
        print(f"\n  {C_ACC}Registrant{RESET}")
        for label, value in reg_fields:
            if value:
                print(f"    {BOX['dot']} {label}: {value}")
    else:
        print(f"\n  {C_MUTE}{BOX['dot']} Registrant information is redacted or unavailable (common under GDPR/privacy).{RESET}")

    # --- Name servers ---
    if record.name_servers:
        print(f"\n  {C_ACC}Name Servers{RESET}")
        for ns in record.name_servers:
            print(f"    {BOX['dot']} {ns.lower()}")

    # --- Status ---
    if record.status:
        print(f"\n  {C_ACC}Status Codes{RESET}")
        for status in record.status:
            key = re.sub(r"\s*\(.*?\)\s*", "", status).strip().lower()
            meaning = EPP_STATUS_GLOSSARY.get(key)
            color = C_CRIT if "hold" in key or "pendingdelete" in key or "redemption" in key else \
                (C_OK if key == "ok" else C_MUTE)
            line = f"    {color}{BOX['dot']} {status}{RESET}"
            if meaning:
                line += f"  {C_MUTE}— {meaning}{RESET}"
            print(line)

    # --- Resolved IPs ---
    if result.resolved_ips:
        print(f"\n  {C_ACC}{BOX['globe']} Resolved IP(s){RESET}")
        for ip in result.resolved_ips:
            print(f"    {BOX['dot']} {ip}")

    # --- Risk factors ---
    if result.risk_factors:
        print(f"\n  {C_ACC}Risk Factors{RESET}")
        sorted_risks = sorted(result.risk_factors, key=lambda r: SEVERITY_ORDER.get(r.severity, 5))
        for risk in sorted_risks:
            color = SEVERITY_COLOR.get(risk.severity, C_MUTE)
            print(f"\n    {color}[{risk.severity}]{RESET} {risk.factor}")
            print(f"      {BOX['tree']} {C_MUTE}{risk.details}{RESET}")
            print(f"      {BOX['treeend']} {color}{BOX['arrow']} {risk.recommendation}{RESET}")

    if verbose and result.raw_whois_snippet:
        print(f"\n  {C_MUTE}Raw WHOIS excerpt:{RESET}")
        for line in result.raw_whois_snippet.splitlines()[:20]:
            if line.strip():
                print(f"    {C_MUTE}{line.strip()}{RESET}")

    # --- Executive summary ---
    critical = [r for r in result.risk_factors if r.severity == "CRITICAL"]
    high = [r for r in result.risk_factors if r.severity == "HIGH"]
    print()
    if critical:
        print(f"  {C_CRIT}{BOX['warn']} CRITICAL ISSUES DETECTED — {len(critical)} issue(s) need immediate attention.{RESET}")
    elif high:
        print(f"  {C_HIGH}{BOX['warn']} HIGH-RISK FACTORS DETECTED — {len(high)} issue(s) worth investigating promptly.{RESET}")
    else:
        print(f"  {C_OK}{BOX['check']} No critical or high-risk issues detected.{RESET}")


def print_summary(results: List[ScanResult]):
    section("SCAN SUMMARY", Fore.MAGENTA)
    scanned = [r for r in results if not r.error]
    errored = [r for r in results if r.error]

    counts = {}
    for r in scanned:
        counts[r.worst_severity] = counts.get(r.worst_severity, 0) + 1

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if level in counts:
            color = SEVERITY_COLOR.get(level, C_MUTE)
            dots = (BOX["dot"] * counts[level]) if UNICODE_OK else ("*" * counts[level])
            print(f"  {color}{level:<9}{RESET} : {color}{counts[level]:>3}{RESET}  {color}{dots}{RESET}")

    if errored:
        print(f"\n  {C_MUTE}{len(errored)} domain(s) could not be looked up.{RESET}")
    print(f"\n  {BOLD}Total domains scanned:{RESET} {len(results)}")
    print()


def save_json(results: List[ScanResult], path: str):
    data = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": AUTHOR,
        "organization": ORG,
        "results": [
            {
                "domain": r.domain,
                "error": r.error,
                "duration_s": r.duration_s,
                "resolved_ips": r.resolved_ips,
                "record": asdict(r.record) if r.record else None,
                "risk_factors": [asdict(f) for f in r.risk_factors],
            }
            for r in results
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def save_csv(results: List[ScanResult], path: str):
    fields = ["domain", "registrar", "creation_date", "expiration_date",
              "worst_severity", "risk_count", "error"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "domain": r.domain,
                "registrar": r.record.registrar if r.record else None,
                "creation_date": format_date(r.record.creation_date) if r.record else None,
                "expiration_date": format_date(r.record.expiration_date) if r.record else None,
                "worst_severity": r.worst_severity,
                "risk_count": len(r.risk_factors),
                "error": r.error,
            })


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def load_domains(args) -> List[str]:
    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.list:
        if not os.path.isfile(args.list):
            print(C_CRIT + f"[!] File not found: {args.list}" + RESET)
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            domains.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
    return domains


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domainsentinel",
        description=f"{TOOL_NAME} — Domain Registration & Ownership Intelligence by {AUTHOR} ({ORG})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  domainsentinel.py -d example.com\n"
            "  domainsentinel.py -d example.com --resolve -v\n"
            "  domainsentinel.py -l domains.txt --threads 3 -o report.json\n"
        ),
    )
    parser.add_argument("-d", "--domain", help="Domain to look up (e.g. example.com)")
    parser.add_argument("-l", "--list", help="File containing a list of domains (one per line)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="WHOIS/DNS timeout in seconds (default: 15)")
    parser.add_argument("--threads", type=int, default=3,
                         help="Concurrent domain lookups (default: 3 — keep modest, WHOIS servers rate-limit)")
    parser.add_argument("--resolve", action="store_true", help="Also resolve the domain's current DNS A/AAAA records")
    parser.add_argument("-o", "--output", help="Save results to file (.json or .csv, inferred from extension)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show a raw WHOIS response excerpt")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{VERSION} — by {AUTHOR} ({ORG})")
        return

    if not args.no_banner:
        render_banner()

    domains = load_domains(args)
    if not domains:
        parser.print_help()
        print(C_CRIT + "\n[!] No domain provided. Use -d/--domain or -l/--list.\n" + RESET)
        sys.exit(1)

    section(f"LOOKING UP {len(domains)} DOMAIN(S)", Fore.CYAN)
    print(f"  {C_MUTE}timeout={args.timeout}s  threads={args.threads}  resolve={'on' if args.resolve else 'off'}{RESET}")

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(scan_domain, d, args.timeout, args.resolve): d
            for d in domains
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    order = {normalize_domain(d): i for i, d in enumerate(domains)}
    results.sort(key=lambda r: order.get(r.domain, 0))

    for result in results:
        print_result(result, args.verbose)

    print()
    print_summary(results)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".csv":
            save_csv(results, args.output)
        else:
            save_json(results, args.output)
        print(C_OK + f"{BOX['check']} Report saved to: {args.output}\n" + RESET)

    hr(C_MUTE, 70)
    print(C_ACC + f"  {TOOL_NAME} · Made by {AUTHOR} — Founder & CEO of {ORG}" + RESET)
    print(C_MUTE + f"  {SITE}  |  {PORTFOLIO}" + RESET)
    hr(C_MUTE, 70)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C_MED + "\n\n[!] Interrupted by user. Exiting.\n" + RESET)
        sys.exit(130)
