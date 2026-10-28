# Incident Report: phish_invoice_attachment.eml

- **Analysed (UTC):** 2026-10-28T08:16:41+00:00
- **Subject:** Final notice - Invoice #88213 payment failed
- **From:** Accounts Payable <billing@invoices-dept.example>
- **Reply-To:** n/a
- **Return-Path:** <billing@invoices-dept.example>
- **Authentication:** SPF=softfail, DKIM=fail, DMARC=fail

## Verdict: HIGH (risk score 100/100)

**Recommended action:** ESCALATE to Cyber Defence / Incident Response. Block sender and URLs, search mailboxes for the same email, remove from inboxes, and advise the reporter not to interact with it.

## Findings

- (+15) SPF = softfail
- (+15) DKIM = fail
- (+15) DMARC = fail
- (+20) Urgency / social-engineering language: action required, final notice, immediately, payment failed
- (+30) Risky attachment type: Invoice_88213.pdf.exe
- (+25) Double extension disguise: Invoice_88213.pdf.exe

## Indicators of Compromise (IOCs)

**URLs / domains**

- None

**Attachments**

- `Invoice_88213.pdf.exe` (81 bytes) - risky extension .exe, double extension
  - SHA-256: `95efa8594152a9c37969315e36a4abfc4366f1a6237cd7847f8c6335ff3914a8`

## Reporter response (template)

Thank you for reporting this email. It is malicious/suspicious. Please do not click links or open attachments, and delete it. Our team is taking action.
