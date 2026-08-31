---
title: Authentication Bypass Vulnerability in Pangolin
slug: 2026-08-pangolin-auth-bypass
description: Pangolin versions prior to 1.22.0 are vulnerable to an authentication bypass in the share-link endpoint, allowing unauthenticated access to arbitrary resources.
date: "2026-08-31T19:58:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pangolin:pangolin:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-72001
  - vulnerability
vendors:
  - Pangolin
products:
  - Pangolin (< 1.22.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The vulnerability allows unauthenticated attackers to access any protected resource by supplying an attacker-controlled URL parameter.
    confidence_band: high
cves:
  - id: CVE-2026-72001
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72001
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Pangolin to version 1.22.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies version 1.22.0 as the fix for CVE-2026-72001
  mitigation_plan:
    - priority: immediate
      action: Disable share-link functionality
      owner: IT Operations
      addresses: CVE-2026-72001
      evidence: Vulnerability resides within the share-link authentication endpoint
---

Pangolin versions prior to 1.22.0 contain a critical authentication bypass vulnerability (CVE-2026-72001) within the application's share-link authentication mechanism. This flaw stems from improper input validation during the token verification process. Specifically, the share-link authentication endpoint fails to enforce the inclusion of the resource identifier in the verification call, allowing an attacker to manipulate URL parameters to gain unauthorized access to protected content. By utilizing a single valid share link - which can be obtained for any low-security resource - an attacker can bypass all configured authentication controls, including SSO, resource passwords, PIN requirements, email allowlists, and header-based authentication. This allows for unauthorized traversal and access to arbitrary resources across different organizations within the Pangolin ecosystem. The vulnerability is rated with a CVSS 3.1 base score of 8.1, indicating high risk for organizations relying on Pangolin for secure document or resource sharing.

## Impact

Successful exploitation of CVE-2026-72001 grants unauthenticated attackers the ability to access any resource managed by the Pangolin platform. This potential exposure includes sensitive proprietary information, internal documents, and collaborative data protected by organizational security policies. Because the vulnerability bypasses SSO and other robust authentication layers, organizations are at immediate risk of large-scale data exfiltration and unauthorized information disclosure across multi-tenant environments.

## Recommendation

* Upgrade Pangolin to version 1.22.0 or later immediately to address the vulnerability in the share-link authentication endpoint.
* Audit access logs for the share-link endpoints for anomalous query patterns where the resource identifier is missing or mismatched from the expected token payload.
* Disable public share links for highly sensitive resources until the patch is applied.
