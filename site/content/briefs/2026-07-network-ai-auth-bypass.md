---
title: Authorization Bypass in Network-AI npm Package CVE-2026-64622
slug: 2026-07-network-ai-auth-bypass
description: 'Network-AI (npm: network-ai) versions 5.12.2 through 5.13.3 are vulnerable to an authorization bypass (CVE-2026-64622) that allows unauthenticated actors to access sensitive approval request details via specific GET read routes like /approvals/. This vulnerability discloses critical information such as shell-command strings, file paths, justifications, and risk levels. Additionally, a hardcoded ''Access-Control-Allow-Origin: *'' header in responses facilitates cross-origin data disclosure, enabling potential exfiltration from malicious websites an operator might visit.'
date: "2026-07-20T12:31:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authorization-bypass
  - information-disclosure
  - npm
vendors:
  - Network-AI
products:
  - 'Network-AI (npm: network-ai) (versions 5.12.2 through 5.13.3)'
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The GET /approvals/?status=all, GET /approvals/:id, GET /approvals/stats, and GET /approvals/sse routes disclose full ApprovalEntry content including action/target shell-command strings, file paths, justifications, and risk levels.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: 'All responses also carry a hardcoded Access-Control-Allow-Origin: * header, enabling cross-origin disclosure from any website the operator visits.'
    confidence_band: high
cves:
  - id: CVE-2026-64622
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64622
rules:
  - title: Detect CVE-2026-64622 Exploitation Attempts on Network-AI
    description: Detects exploitation attempts for CVE-2026-64622, an authorization bypass in network-ai, by monitoring unauthenticated GET requests to sensitive /approvals/ routes.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-64622 impacts `network-ai` npm package versions 5.12.2 through 5.13.3, allowing unauthenticated actors to bypass authorization checks on specific GET read routes related to the `ApprovalInbox`. This flaw means that even when a secret is configured, sensitive approval request details become accessible without authentication. The affected routes, including `/approvals/?status=all`, `/approvals/:id`, `/approvals/stats`, and `/approvals/sse`, disclose full `ApprovalEntry` content such as action/target shell-command strings, file paths, justifications, and risk levels. Compounding the issue, all responses from these routes carry a hardcoded `Access-Control-Allow-Origin: *` header, which facilitates cross-origin data disclosure. This allows malicious websites, if visited by an operator, to potentially exfiltrate the exposed sensitive data. This vulnerability represents an incomplete fix for a previously identified issue (GHSA-mxjx-28vx-xjjj).

## Attack Chain

1. An unauthenticated attacker identifies a `network-ai` instance running vulnerable versions 5.12.2 through 5.13.3.
2. The attacker sends an unauthenticated HTTP GET request to one of the vulnerable `ApprovalInbox` read routes, such as `/approvals/?status=all`, `/approvals/:id`, `/approvals/stats`, or `/approvals/sse`.
3. Due to the CVE-2026-64622 authorization bypass, the `network-ai` application fails to apply the configured `checkAuth/secret`.
4. The application responds with full `ApprovalEntry` content, which includes sensitive data like shell-command strings, file paths, justifications, and risk levels, without requiring authentication.
5. The response also contains a hardcoded `Access-Control-Allow-Origin: *` header, making the disclosed data vulnerable to cross-origin access.
6. If an operator of the `network-ai` application visits a malicious website, that website can initiate cross-origin requests to the vulnerable `network-ai` instance.
7. The malicious website successfully retrieves the sensitive approval data and exfiltrates it to an attacker-controlled server.

## Impact

Successful exploitation of CVE-2026-64622 leads to unauthorized disclosure of highly sensitive information, including critical operational details like shell-command strings, internal file paths, and business justifications for approvals. This exposure can provide attackers with valuable intelligence for further attacks, potentially leading to privilege escalation, system compromise, or data manipulation. The hardcoded `Access-Control-Allow-Origin: *` header also enables severe privacy and data exfiltration risks, as any visited malicious website could programmatically extract this sensitive data, impacting organizations using the vulnerable versions.

## Recommendation

* Patch CVE-2026-64622 by immediately updating the `network-ai` npm package to a version outside the affected range (i.e., higher than 5.13.3 or lower than 5.12.2 if applicable).
* Deploy the Sigma rule "Detect CVE-2026-64622 Exploitation Attempts on Network-AI" to your SIEM solution to alert on suspicious access patterns.
* Monitor web server access logs for unauthenticated GET requests to the `/approvals/?status=all`, `/approvals/:id`, `/approvals/stats`, and `/approvals/sse` endpoints, referencing the log source category `webserver`.
* Implement Web Application Firewall (WAF) rules to restrict or block unauthenticated access to the `network-ai` `/approvals/*` paths mentioned in the attack chain, if not required for legitimate operations.
