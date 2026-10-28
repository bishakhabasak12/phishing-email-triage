#!/usr/bin/env python3
"""
Phishing Email Triage Tool
--------------------------
Parses a .eml file, extracts indicators of compromise (IOCs), scores the
email, assigns a severity (Low / Medium / High) and writes an incident
report (Markdown + JSON).

Usage:
    python triage.py samples/phish_bank.eml
    python triage.py samples/            # triage every .eml in a folder
    VT_API_KEY=xxxx python triage.py samples/ --vt   # add VirusTotal lookups

Educational / defensive use only. Never open real attachments or click
real links from a suspicious email on your own machine.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Detection knowledge
# --------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "country", "kim", "loan", "rest", "icu",
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
}
DANGEROUS_EXT = {
    "exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "com", "pif",
    "lnk", "iso", "img", "hta", "jar", "msi", "ps1", "wsf", "docm",
    "xlsm", "pptm", "html", "htm", "svg", "one",
}
URGENCY_PHRASES = [
    "urgent", "immediately", "within 24 hours", "account suspended",
    "account will be closed", "verify your account", "confirm your identity",
    "unusual activity", "final notice", "action required", "password expires",
    "payment failed", "click here", "limited time", "security alert",
]
BRAND_KEYWORDS = [
    "paypal", "microsoft", "office365", "google", "apple", "amazon",
    "netflix", "bank", "dhl", "fedex", "hdfc", "sbi", "icici", "irs",
]
IP_URL = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
AUTH_REGEX = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class LinkParser(HTMLParser):
    """Collects (href, visible text) pairs from HTML bodies."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(address: str) -> str:
    addr = parseaddr(address)[1]
    return addr.split("@")[-1].lower().strip(">") if "@" in addr else ""


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def base_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def defang(text: str) -> str:
    """Make URLs/domains safe to paste into reports (hxxp, [.])."""
    return text.replace("http", "hxxp").replace(".", "[.]")


# --------------------------------------------------------------------------
# Core analysis
# --------------------------------------------------------------------------
def parse_email(path: Path):
    with open(path, "rb") as fh:
        return BytesParser(policy=policy.default).parse(fh)


def extract_bodies(msg):
    text, html = "", ""
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            if ctype == "text/plain":
                text += part.get_content()
            elif ctype == "text/html":
                html += part.get_content()
        except Exception:
            continue
    return text, html


def extract_attachments(msg):
    out = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        out.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "md5": hashlib.md5(payload).hexdigest(),
        })
    return out


def analyse(path: Path) -> dict:
    msg = parse_email(path)
    findings = []  # (points, description)

    def flag(points, desc):
        findings.append((points, desc))

    # ---- Header basics ----------------------------------------------------
    from_hdr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    subject = str(msg.get("Subject", ""))
    display_name, from_addr = parseaddr(from_hdr)
    from_domain = domain_of(from_hdr)

    # ---- Authentication results ------------------------------------------
    auth = {}
    for hdr in (msg.get_all("Authentication-Results") or []) + (
        msg.get_all("Received-SPF") or []
    ):
        for mech, result in AUTH_REGEX.findall(str(hdr)):
            auth.setdefault(mech.lower(), result.lower())
    spf_line = str(msg.get("Received-SPF", "")).split(" ")[0].lower()
    if "spf" not in auth and spf_line in {"pass", "fail", "softfail", "neutral", "none"}:
        auth["spf"] = spf_line

    for mech in ("spf", "dkim", "dmarc"):
        result = auth.get(mech)
        if result is None:
            flag(5, f"{mech.upper()} result missing from headers")
        elif result in {"fail", "softfail", "permerror", "temperror"}:
            flag(15, f"{mech.upper()} = {result}")

    # ---- Sender mismatches -------------------------------------------------
    if reply_to and domain_of(reply_to) and domain_of(reply_to) != from_domain:
        flag(20, f"Reply-To domain ({domain_of(reply_to)}) differs from From domain ({from_domain})")
    if return_path and domain_of(return_path) and base_domain(domain_of(return_path)) != base_domain(from_domain):
        flag(15, f"Return-Path domain ({domain_of(return_path)}) differs from From domain ({from_domain})")

    # Display-name spoofing: brand/name in display name, unrelated sender domain
    dn_lower = display_name.lower()
    for brand in BRAND_KEYWORDS:
        if brand in dn_lower and brand not in from_domain:
            flag(30, f"Possible display-name spoofing: '{display_name}' sent from {from_domain}")
            break
    if "@" in display_name and domain_of(display_name) != from_domain:
        flag(20, "Display name contains a different email address than the real sender")

    # ---- Body: urgency + URLs ---------------------------------------------
    text_body, html_body = extract_bodies(msg)
    combined = f"{subject}\n{text_body}\n{html_body}".lower()
    hits = sorted({p for p in URGENCY_PHRASES if p in combined})
    if hits:
        flag(min(5 * len(hits), 20), f"Urgency / social-engineering language: {', '.join(hits)}")

    parser = LinkParser()
    parser.feed(html_body)
    urls = {}
    for href, shown in parser.links:
        if href and href.lower().startswith(("http://", "https://")):
            urls[href] = shown
    for u in URL_REGEX.findall(text_body + " " + html_body):
        urls.setdefault(u.rstrip(".,;"), "")

    url_results = []
    for url, shown in urls.items():
        host = host_of(url)
        notes = []
        if not host:
            continue
        if IP_URL.match(host):
            notes.append("IP address instead of domain"); flag(20, f"URL uses raw IP: {defang(url)}")
        if host.startswith("xn--") or ".xn--" in host:
            notes.append("punycode / homograph risk"); flag(20, f"Punycode domain: {defang(host)}")
        if host in URL_SHORTENERS:
            notes.append("URL shortener"); flag(10, f"URL shortener used: {defang(host)}")
        if host.split(".")[-1] in SUSPICIOUS_TLDS:
            notes.append("suspicious TLD"); flag(10, f"Suspicious TLD: {defang(host)}")
        if url.lower().startswith("http://"):
            notes.append("no HTTPS"); flag(5, f"Unencrypted link: {defang(url)}")
        if host.count(".") >= 4:
            notes.append("excessive subdomains"); flag(10, f"Excessive subdomains: {defang(host)}")
        # Link text shows one domain but href goes elsewhere
        shown_host = host_of(shown) if shown.lower().startswith("http") else ""
        if shown_host and base_domain(shown_host) != base_domain(host):
            notes.append("link text does not match destination")
            flag(25, f"Deceptive link: text shows {defang(shown_host)} but goes to {defang(host)}")
        if from_domain and base_domain(host) != base_domain(from_domain):
            notes.append("domain differs from sender")
        url_results.append({
            "url": url, "defanged": defang(url), "host": host,
            "link_text": shown, "notes": notes,
        })

    # ---- Attachments --------------------------------------------------------
    attachments = extract_attachments(msg)
    for att in attachments:
        name = att["filename"].lower()
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        att["flags"] = []
        if ext in DANGEROUS_EXT:
            att["flags"].append(f"risky extension .{ext}")
            flag(30, f"Risky attachment type: {att['filename']}")
        if len(parts) > 2 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"} and ext in DANGEROUS_EXT:
            att["flags"].append("double extension")
            flag(25, f"Double extension disguise: {att['filename']}")
        if ext in {"zip", "rar", "7z"}:
            att["flags"].append("archive (inspect contents in sandbox)")
            flag(10, f"Archive attachment: {att['filename']}")

    # ---- Score -> severity ---------------------------------------------------
    score = min(sum(p for p, _ in findings), 100)
    if score >= 50:
        severity = "High"
        action = ("ESCALATE to Cyber Defence / Incident Response. Block sender and URLs, "
                  "search mailboxes for the same email, remove from inboxes, "
                  "and advise the reporter not to interact with it.")
    elif score >= 20:
        severity = "Medium"
        action = ("Investigate further: check IOCs on threat-intel sources, confirm with "
                  "the reporter, and block/monitor if confirmed malicious.")
    else:
        severity = "Low"
        action = ("Likely benign or spam. Reply to the reporter with guidance, "
                  "close the ticket and log it for pattern tracking.")

    return {
        "file": path.name,
        "analysed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subject": subject,
        "from": from_hdr,
        "reply_to": reply_to,
        "return_path": return_path,
        "authentication": auth,
        "urls": url_results,
        "attachments": attachments,
        "findings": [{"points": p, "detail": d} for p, d in findings],
        "score": score,
        "severity": severity,
        "recommended_action": action,
        "virustotal": [],
    }


# --------------------------------------------------------------------------
# Optional VirusTotal enrichment (needs VT_API_KEY and internet)
# --------------------------------------------------------------------------
def vt_lookup(result: dict):
    key = os.environ.get("VT_API_KEY")
    if not key:
        print("  [!] --vt given but VT_API_KEY is not set; skipping.", file=sys.stderr)
        return
    try:
        import requests
    except ImportError:
        print("  [!] 'requests' not installed (pip install requests); skipping VT.", file=sys.stderr)
        return

    headers = {"x-apikey": key}
    targets = [("file", a["sha256"], a["filename"]) for a in result["attachments"]]
    for u in result["urls"]:
        uid = base64.urlsafe_b64encode(u["url"].encode()).decode().strip("=")
        targets.append(("url", uid, u["defanged"]))

    for kind, ident, label in targets:
        endpoint = "files" if kind == "file" else "urls"
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}/{ident}",
                             headers=headers, timeout=15)
        except requests.RequestException as exc:
            print(f"  [!] VT request failed: {exc}", file=sys.stderr)
            continue
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal = stats.get("malicious", 0) + stats.get("suspicious", 0)
            result["virustotal"].append({"type": kind, "indicator": label,
                                         "malicious_or_suspicious": mal, "stats": stats})
            if mal > 0:
                result["findings"].append({"points": 40, "detail": f"VirusTotal: {mal} engines flag {label}"})
                result["score"] = min(result["score"] + 40, 100)
        elif r.status_code == 404:
            result["virustotal"].append({"type": kind, "indicator": label, "note": "not found in VT"})
        else:
            print(f"  [!] VT returned {r.status_code} for {label}", file=sys.stderr)
    # Re-grade after enrichment
    if result["score"] >= 50:
        result["severity"] = "High"


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def to_markdown(r: dict) -> str:
    lines = [
        f"# Incident Report: {r['file']}", "",
        f"- **Analysed (UTC):** {r['analysed_at']}",
        f"- **Subject:** {r['subject']}",
        f"- **From:** {r['from']}",
        f"- **Reply-To:** {r['reply_to'] or 'n/a'}",
        f"- **Return-Path:** {r['return_path'] or 'n/a'}",
        f"- **Authentication:** " + (", ".join(f"{k.upper()}={v}" for k, v in r["authentication"].items()) or "none found"),
        "", f"## Verdict: {r['severity'].upper()} (risk score {r['score']}/100)", "",
        f"**Recommended action:** {r['recommended_action']}", "",
        "## Findings", "",
    ]
    if r["findings"]:
        lines += [f"- (+{f['points']}) {f['detail']}" for f in r["findings"]]
    else:
        lines.append("- No suspicious indicators detected.")

    lines += ["", "## Indicators of Compromise (IOCs)", "", "**URLs / domains**", ""]
    if r["urls"]:
        for u in r["urls"]:
            note = f" - {', '.join(u['notes'])}" if u["notes"] else ""
            lines.append(f"- `{u['defanged']}`{note}")
    else:
        lines.append("- None")
    lines += ["", "**Attachments**", ""]
    if r["attachments"]:
        for a in r["attachments"]:
            fl = f" - {', '.join(a['flags'])}" if a.get("flags") else ""
            lines.append(f"- `{a['filename']}` ({a['size_bytes']} bytes){fl}")
            lines.append(f"  - SHA-256: `{a['sha256']}`")
    else:
        lines.append("- None")
    if r["virustotal"]:
        lines += ["", "## VirusTotal Enrichment", ""]
        for v in r["virustotal"]:
            detail = v.get("note") or f"{v['malicious_or_suspicious']} detections"
            lines.append(f"- {v['indicator']}: {detail}")
    lines += ["", "## Reporter response (template)", "",
              "Thank you for reporting this email. " +
              ("It is malicious/suspicious. Please do not click links or open attachments, "
               "and delete it. Our team is taking action." if r["severity"] != "Low" else
               "We reviewed it and found no strong signs of phishing, but stay cautious "
               "and report anything similar."), ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Phishing email triage tool")
    ap.add_argument("target", help=".eml file or a folder of .eml files")
    ap.add_argument("--out", default="reports", help="output folder (default: reports)")
    ap.add_argument("--vt", action="store_true", help="enrich IOCs with VirusTotal (needs VT_API_KEY)")
    args = ap.parse_args()

    target = Path(args.target)
    files = sorted(target.glob("*.eml")) if target.is_dir() else [target]
    if not files:
        sys.exit("No .eml files found.")

    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)
    summary = []
    for f in files:
        print(f"Analysing {f.name} ...")
        result = analyse(f)
        if args.vt:
            vt_lookup(result)
        (out_dir / f"{f.stem}.md").write_text(to_markdown(result), encoding="utf-8")
        (out_dir / f"{f.stem}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        summary.append(result)
        print(f"  -> {result['severity']} (score {result['score']})")

    # Summary table for the whole batch
    rows = ["# Triage Summary", "", "| File | Severity | Score | Subject |", "|---|---|---|---|"]
    for r in sorted(summary, key=lambda x: -x["score"]):
        rows.append(f"| {r['file']} | {r['severity']} | {r['score']} | {r['subject']} |")
    (out_dir / "SUMMARY.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"\nReports written to {out_dir}/")


if __name__ == "__main__":
    main()
