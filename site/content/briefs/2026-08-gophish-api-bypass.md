---
title: Gophish API Authentication Middleware Bypass
slug: 2026-08-gophish-api-bypass
description: Gophish versions through 0.12.1 contain a vulnerability in the API authentication middleware that fails to enforce account lockout and password change requirements, allowing attackers with valid API keys to maintain persistent unauthorized access.
date: "2026-08-28T21:38:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gophish:gophish:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - api-security
vendors:
  - Gophish
products:
  - Gophish (<= 0.12.1)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers with valid API keys can bypass these security controls and retain full API access even when their account is locked or password change is required.
    confidence_band: high
cves:
  - id: CVE-2026-82269
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82269
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit active Gophish API keys against current user status
      owner: SOC
      due: 24h
      evidence: CVE-2026-82269 metadata
  mitigation_plan:
    - priority: immediate
      action: Restrict API endpoint network access to trusted management subnets
      owner: IT Operations
      addresses: CVE-2026-82269
      evidence: NVD vulnerability disclosure
---

Gophish versions through 0.12.1 contain a critical security flaw (CVE-2026-82269) within the application's API authentication middleware. The implementation fails to correctly enforce account security policies, specifically account lockout states and mandatory password rotation requirements, when authentication is performed via the API. This vulnerability allows an attacker who has acquired a valid API key to bypass these security constraints. Even if an administrator disables an account or mandates a password reset for compromised credentials, the API middleware continues to honor existing, valid API keys. This enables persistent access to sensitive data and Gophish operational controls despite intended account restrictions. Defenders should identify all active API keys in their environment and verify them against the status of the associated user accounts until the software can be patched to a version that properly integrates state checks into the API authentication logic.

## Impact

Successful exploitation allows for unauthorized persistence and potential privilege escalation within a Gophish deployment. By bypassing lockout and password change requirements, an attacker can maintain long-term access to phishing campaign configurations, sensitive target data, and administrative API endpoints. This significantly lowers the barrier for attackers to maintain access after a primary credential compromise has been detected and mitigated by an administrator.

## Recommendation

- Perform an audit of all active Gophish API keys and cross-reference them with currently active and compliant user accounts.
- Review Gophish API access logs to identify anomalous or unauthorized persistent connections.
- Upgrade Gophish to a version beyond 0.12.1 once the vendor provides a patch addressing CVE-2026-82269.
- Implement restrictive network access control lists (ACLs) to limit access to Gophish API endpoints to known, trusted management IP addresses.
