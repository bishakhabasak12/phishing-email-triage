# Incident Report: phish_m365_credential.eml

- **Analysed (UTC):** 2026-10-28T08:16:41+00:00
- **Subject:** Security alert: your password expires today
- **From:** Microsoft 365 Support <it-support@company-it-helpdesk.example>
- **Reply-To:** n/a
- **Return-Path:** <it-support@company-it-helpdesk.example>
- **Authentication:** SPF=pass, DKIM=none, DMARC=none

## Verdict: HIGH (risk score 55/100)

**Recommended action:** ESCALATE to Cyber Defence / Incident Response. Block sender and URLs, search mailboxes for the same email, remove from inboxes, and advise the reporter not to interact with it.

## Findings

- (+30) Possible display-name spoofing: 'Microsoft 365 Support' sent from company-it-helpdesk.example
- (+15) Urgency / social-engineering language: password expires, security alert, verify your account
- (+10) Excessive subdomains: m365-portal[.]secure[.]verify[.]account-check[.]example

## Indicators of Compromise (IOCs)

**URLs / domains**

- `hxxps://login[.]microsoftonline[.]com` - domain differs from sender
- `hxxps://m365-portal[.]secure[.]verify[.]account-check[.]example/login` - excessive subdomains, domain differs from sender

**Attachments**

- None

## Reporter response (template)

Thank you for reporting this email. It is malicious/suspicious. Please do not click links or open attachments, and delete it. Our team is taking action.
