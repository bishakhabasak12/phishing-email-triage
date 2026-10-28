# Phishing Email Triage Tool

A Python command-line tool that triages suspicious emails the way a SOC / security-mailbox analyst would: it parses a `.eml` file, extracts indicators of compromise (IOCs), scores the risk, assigns a severity, recommends an action, and writes an incident report.

Built as a hands-on project to practise the workflow of monitoring a security mailbox: **screen, classify, investigate, escalate, document.**

## What it checks

| Area | Checks |
|---|---|
| Authentication | SPF, DKIM and DMARC results from the headers |
| Sender | From vs Reply-To vs Return-Path mismatches, display-name spoofing of known brands |
| Links | Raw-IP URLs, URL shorteners, suspicious TLDs, punycode, excessive subdomains, no HTTPS, link text that does not match the real destination |
| Attachments | Risky extensions, double extensions (e.g. `invoice.pdf.exe`), archives, SHA-256 / MD5 hashes |
| Content | Urgency and social-engineering language |
| Enrichment (optional) | VirusTotal lookups for attachment hashes and URLs |

## Severity and response

| Score | Severity | Recommended action |
|---|---|---|
| 0-19 | Low | Reply with guidance, close, log for pattern tracking |
| 20-49 | Medium | Investigate IOCs, confirm with reporter, block or monitor |
| 50+ | High | Escalate to Cyber Defence / Incident Response, block, search and purge mailboxes |

Each report also includes **defanged IOCs** (`hxxp://evil[.]example`) so they can be shared safely, and a reply template for the reporter.

## Usage

```bash
pip install -r requirements.txt        # only needed for --vt

python triage.py samples/phish_bank.eml        # one email
python triage.py samples/                      # whole folder
VT_API_KEY=your_key python triage.py samples/ --vt   # add VirusTotal enrichment
```

Output goes to `reports/`: one `.md` and one `.json` per email, plus `SUMMARY.md` ranking the batch.

## Sample results

| File | Severity | Score |
|---|---|---|
| phish_bank.eml | High | 100 |
| phish_invoice_attachment.eml | High | 100 |
| phish_m365_credential.eml | High | 55 |
| legit_newsletter.eml | Low | 0 |

The samples in `samples/` are **synthetic** emails built on reserved `.example` domains and documentation IP ranges. The "attachment" is plain harmless text. Add your own real samples (e.g. from public phishing datasets) and review them in a sandbox, never on your main machine.

## How to extend it

- Parse the `Received` chain to trace the sending path
- Add URL expansion for shorteners in a safe sandbox
- Add AbuseIPDB / URLScan.io lookups
- Auto-generate a ticket (JIRA-style) from each report
- Track repeat senders and domains to spot recurring attack patterns

## Limitations

This is a rule-based triage aid, not a replacement for analyst judgement. Scores are heuristics and will produce false positives and false negatives.
