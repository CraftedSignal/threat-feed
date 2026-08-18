---
title: SSRF Vulnerability in AWX Webhook Callback Mechanism (CVE-2026-71365)
slug: 2026-08-awx-ssrf
description: An SSRF vulnerability in the AWX webhook status callback mechanism allows attackers with template-level administrative access to exfiltrate Git Personal Access Tokens via forged webhook payloads.
date: "2026-08-18T16:55:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webserver
  - ssrf
  - credential-theft
  - vulnerability
vendors:
  - Red Hat
products:
  - AWX
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A user with admin role on a webhook-enabled job template can read the template's webhook signing key, forge a signed GitHub webhook payload with an arbitrary statuses_url
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: The status update request includes the configured Git Personal Access Token (PAT) in the Authorization header, resulting in credential leakage
    confidence_band: high
cves:
  - id: CVE-2026-71365
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71365
---

CVE-2026-71365 is a critical server-side request forgery (SSRF) vulnerability identified in the AWX automation platform. The flaw exists within the webhook status callback mechanism, specifically when processing incoming GitHub pull request webhooks. AWX extracts the status callback URL from the payload without performing validation against expected Git provider domains. 

An attacker who possesses administrative rights on a job template configured for webhooks can access the template's webhook signing key. This access allows the attacker to forge a signed GitHub webhook payload containing a malicious 'statuses_url'. When AWX processes this forged payload, it sends an authenticated HTTP POST request to the attacker-defined URL. Because the request includes the configured Git Personal Access Token (PAT) within the Authorization header, this vulnerability enables the silent exfiltration of credentials to external or internal attacker-controlled endpoints. 

## Impact

The impact of this vulnerability is significant, as it facilitates the unauthorized exfiltration of Git Personal Access Tokens used for integration with version control systems. Organizations utilizing AWX for automated job templates are at risk of losing service account credentials, which could lead to further unauthorized access, code repository tampering, or lateral movement within the development pipeline.

## Recommendation

- Audit all AWX job templates configured for webhooks to identify and restrict administrative access.
- Implement egress filtering at the network level to prevent AWX server instances from initiating connections to unauthorized or untrusted external domains.
- Review access logs and audit trails for job templates to identify potentially unauthorized webhook configuration changes.
- Monitor AWX server outbound traffic logs for unexpected POST requests directed toward non-Git provider infrastructure.
- Patch AWX to the latest version provided by Red Hat that addresses CVE-2026-71365.
