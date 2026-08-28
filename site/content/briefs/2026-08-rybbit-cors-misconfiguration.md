---
title: 'CVE-2026-82287: CORS Misconfiguration in Rybbit'
slug: 2026-08-rybbit-cors-misconfiguration
description: A CORS misconfiguration in Rybbit versions prior to 2.7.0 allows unauthorized cross-origin requests to read sensitive data and perform authenticated actions.
date: "2026-08-28T21:39:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:rybbit:rybbit:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - cors
  - cve-2026-82287
vendors:
  - Rybbit
products:
  - Rybbit (< 2.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify System Firewall'
    evidence: Rybbit before 2.7.0 contains a CORS misconfiguration vulnerability that allows attackers to bypass origin restrictions.
    confidence_band: high
cves:
  - id: CVE-2026-82287
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82287
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Rybbit to version 2.7.0 or later
      owner: IT Operations
      addresses: CVE-2026-82287
      evidence: Rybbit before 2.7.0 contains a CORS misconfiguration vulnerability
---

Rybbit versions prior to 2.7.0 are vulnerable to a Cross-Origin Resource Sharing (CORS) misconfiguration (CVE-2026-82287). The application improperly validates request origins, reflecting any provided origin in the Access-Control-Allow-Origin response header while simultaneously allowing credentials (Access-Control-Allow-Credentials: true). This vulnerability allows an attacker to craft a malicious website that forces an authenticated Rybbit user's browser to send credentialed requests to the Rybbit application. The server's response allows the attacker's origin to read sensitive data, including analytics and account information. Furthermore, because credentials are included, the attacker can execute authenticated state-changing operations on behalf of the victim, such as modifying account settings or exfiltrating private data. This poses a significant risk to user confidentiality and account integrity.

## Impact

Successful exploitation allows unauthenticated attackers to bypass origin restrictions to perform unauthorized actions as an authenticated user. This results in the exposure of sensitive analytics and user account information, and potential account takeover or unauthorized state changes within the application. The impact is assessed at a CVSS v3.1 base score of 8.1, indicating a high level of risk to confidentiality and integrity for users of Rybbit deployments.

## Recommendation

Prioritized actions for security teams managing Rybbit instances:
- Upgrade Rybbit to version 2.7.0 or later immediately to resolve the CORS misconfiguration vulnerability identified in CVE-2026-82287.
- Review web server and application logs for suspicious cross-origin requests originating from unknown or unauthorized domains attempting to access sensitive API endpoints.
- Implement a strict, allow-list-based CORS policy in the application configuration if an immediate upgrade is not feasible, ensuring that only trusted domains are reflected in the Access-Control-Allow-Origin header.
