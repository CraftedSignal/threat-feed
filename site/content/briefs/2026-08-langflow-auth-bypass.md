---
title: Authentication Bypass Vulnerability in IBM Langflow OSS
slug: 2026-08-langflow-auth-bypass
description: IBM Langflow OSS versions 1.0.0 through 1.9.6 are vulnerable to an authentication bypass flaw due to improper restriction of excessive authentication attempts, allowing remote attackers to potentially compromise user accounts.
date: "2026-08-13T22:05:10Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - IBM
products:
  - Langflow OSS (1.0.0 through 1.9.6)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: IBM Langflow OSS 1.0.0 through 1.9.6 could allow a remote attacker to obtain unauthorized access to user accounts due to improper restriction of excessive authentication attempts.
    confidence_band: high
cves:
  - id: CVE-2026-19297
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19297
  - https://www.ibm.com/support/pages/node/7283558
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Langflow OSS instances to a version > 1.9.6
      owner: IT Operations
      due: 48h
      evidence: IBM security advisory recommends version updates.
  mitigation_plan:
    - priority: immediate
      action: Configure rate-limiting on authentication API endpoints
      owner: IT Operations
      addresses: CVE-2026-19297
      evidence: Vulnerability stems from lack of excessive authentication attempt restrictions.
---

IBM Langflow OSS versions 1.0.0 through 1.9.6 contain a critical authentication vulnerability tracked as CVE-2026-19297. This flaw is classified under CWE-307: Improper Restriction of Excessive Authentication Attempts. The vulnerability permits a remote, unauthenticated attacker to execute high-frequency login requests against the application without encountering rate-limiting or account lockout mechanisms. This failure allows for effective brute-force or credential-stuffing attacks, potentially leading to unauthorized access to administrative or user accounts. Given the ease of exploitation (CVSS 3.1 base score of 9.1), defenders should prioritize identifying exposed instances and monitoring authentication endpoints for anomalous traffic patterns.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to user accounts. Depending on the privileges of the targeted account, an attacker could gain full control over the Langflow instance, access sensitive data, or modify workflows. This poses a significant risk to organizations using Langflow OSS for sensitive automation or data processing tasks.

## Recommendation

Prioritized actions for security teams:
- Identify and inventory all internet-facing or internal instances of IBM Langflow OSS 1.0.0 through 1.9.6.
- Upgrade affected Langflow OSS installations to the latest patched version provided by IBM.
- Implement rate limiting or WAF-based blocking for login endpoints if patching cannot be performed immediately.
- Review web server logs for high-frequency POST requests to authentication endpoints originating from single source IPs.
