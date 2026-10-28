# Incident Report: phish_bank.eml

- **Analysed (UTC):** 2026-10-28T08:16:41+00:00
- **Subject:** URGENT: Account suspended - verify your account immediately
- **From:** HDFC Bank Security <alerts@secure-hdfcbank-alerts.example>
- **Reply-To:** support-desk@gmail-helpdesk.example
- **Return-Path:** <bounce@mailer-xk39.example>
- **Authentication:** SPF=fail, DKIM=none, DMARC=fail

## Verdict: HIGH (risk score 100/100)

**Recommended action:** ESCALATE to Cyber Defence / Incident Response. Block sender and URLs, search mailboxes for the same email, remove from inboxes, and advise the reporter not to interact with it.

## Findings

- (+15) SPF = fail
- (+15) DMARC = fail
- (+20) Reply-To domain (gmail-helpdesk.example) differs from From domain (secure-hdfcbank-alerts.example)
- (+15) Return-Path domain (mailer-xk39.example) differs from From domain (secure-hdfcbank-alerts.example)
- (+20) Urgency / social-engineering language: account suspended, account will be closed, action required, click here, confirm your identity, immediately, unusual activity, urgent, verify your account, within 24 hours
- (+20) URL uses raw IP: hxxp://198[.]51[.]100[.]23/hdfc/login[.]php
- (+5) Unencrypted link: hxxp://198[.]51[.]100[.]23/hdfc/login[.]php
- (+25) Deceptive link: text shows www[.]hdfcbank[.]com but goes to 198[.]51[.]100[.]23
- (+10) URL shortener used: bit[.]ly
- (+5) Unencrypted link: hxxp://bit[.]ly/3xFake99

## Indicators of Compromise (IOCs)

**URLs / domains**

- `hxxp://198[.]51[.]100[.]23/hdfc/login[.]php` - IP address instead of domain, no HTTPS, link text does not match destination, domain differs from sender
- `hxxp://bit[.]ly/3xFake99` - URL shortener, no HTTPS, domain differs from sender
- `hxxps://www[.]hdfcbank[.]com/netbanking/verify` - domain differs from sender

**Attachments**

- None

## Reporter response (template)

Thank you for reporting this email. It is malicious/suspicious. Please do not click links or open attachments, and delete it. Our team is taking action.
