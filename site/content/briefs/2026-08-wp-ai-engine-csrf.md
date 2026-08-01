---
title: 'CVE-2026-15988: CSRF Vulnerability in AI Engine WordPress Plugin'
slug: 2026-08-wp-ai-engine-csrf
description: The AI Engine WordPress plugin contains a CSRF vulnerability in the reauth_for_authorize function allowing unauthenticated attackers to create administrator accounts.
date: "2026-08-01T09:49:54Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - The AI Engine – The Chatbot, AI Framework & MCP for WordPress (3.6.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: This makes it possible for unauthenticated attackers to create new administrator accounts with attacker-supplied credentials via a CSRF-based REST authentication bypass.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136.001
    technique_name: 'Create Account: Local Account'
    evidence: This makes it possible for unauthenticated attackers to create new administrator accounts with attacker-supplied credentials.
    confidence_band: high
cves:
  - id: CVE-2026-15988
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15988
rules:
  - title: Detect CVE-2026-15988 Exploitation - Unauthorized reauth_for_authorize Request
    description: Detects potential exploitation of the AI Engine plugin by monitoring for requests to the vulnerable reauth_for_authorize function combined with method overrides.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

The AI Engine - The Chatbot, AI Framework & MCP for WordPress plugin is vulnerable to Cross-Site Request Forgery (CSRF) in all versions up to and including 3.6.5. The vulnerability stems from missing or incorrect nonce validation within the `reauth_for_authorize` function. By leveraging this flaw, an unauthenticated attacker can trick a site administrator into clicking a malicious link, which triggers an unauthorized REST API call. This operation can be combined with WordPress's `?_method=POST` method-override feature to convert a GET request into an authenticated POST request. The impact of this exploit is severe, as it permits the creation of unauthorized administrator accounts, leading to full site compromise and persistent access for the attacker.

## Attack Chain

1. The attacker crafts a malicious URL targeting a WordPress site running the vulnerable AI Engine plugin.
2. The attacker delivers the link to a site administrator via social engineering (e.g., phishing).
3. The administrator, while logged into the WordPress dashboard, clicks the attacker-supplied link.
4. The browser initiates a request to the `reauth_for_authorize` endpoint, which fails to validate a nonce.
5. The attacker utilizes the `?_method=POST` query parameter to override the HTTP method to POST.
6. The REST API processes the request as an authenticated administrative action due to the administrator's active session.
7. The request executes the creation of a new user account with the 'administrator' role using credentials provided by the attacker.
8. The attacker authenticates as the newly created administrator to gain full control over the WordPress instance.

## Impact

Successful exploitation leads to full administrative compromise of the target WordPress site. An attacker gaining administrator-level access can modify site content, redirect traffic, exfiltrate sensitive data, or install further backdoors. The scope of this threat affects any organization utilizing The AI Engine plugin versions 3.6.5 or earlier, posing a significant risk to the integrity and availability of hosted web content.

## Recommendation

Prioritize the following actions for your web security teams:
- Update the AI Engine plugin to version 3.6.6 or higher immediately to apply the vendor-provided security patch.
- Audit the WordPress 'Users' table for unauthorized accounts created during the current reporting period.
- Deploy web server log monitoring to identify suspicious HTTP POST requests directed toward REST API endpoints containing `reauth_for_authorize`.
- Use the provided Sigma rule to monitor for potential exploitation attempts targeting the vulnerable function.
