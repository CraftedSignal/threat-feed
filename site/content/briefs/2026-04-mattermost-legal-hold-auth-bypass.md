---
title: Mattermost Legal Hold Plugin Authentication Bypass Vulnerability
slug: 2026-04-mattermost-legal-hold-auth-bypass
description: Mattermost Legal Hold plugin versions 1.1.4 and earlier allow authenticated attackers to bypass authorization checks, enabling unauthorized access and modification of legal hold data via crafted API requests.
date: "2026-04-06T13:17:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mattermost
  - authentication-bypass
  - legal-hold
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
cves:
  - id: CVE-2026-3524
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3524
  - https://mattermost.com/security-updates
rules:
  - title: Detect Mattermost Legal Hold Plugin Unauthorized API Access
    description: Detects attempts to access the Mattermost Legal Hold plugin API endpoints without proper authorization, indicating potential exploitation of CVE-2026-3524.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.003
    data_sources:
      - webserver
      - linux
  - title: Detect Mattermost Legal Hold Plugin API POST Requests
    description: Detects POST requests to the Mattermost Legal Hold plugin API endpoints. Monitor for unexpected POST activity, which may be related to creation or modification of legal holds by unauthorized users.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Mattermost Legal Hold plugin, in versions 1.1.4 and earlier, contains an authentication bypass vulnerability (CVE-2026-3524) that can be exploited by authenticated attackers. The vulnerability lies in the ServeHTTP function, where a failed authorization check does not properly halt request processing. This flaw allows attackers to craft malicious API requests to the plugin's endpoints, enabling them to access, create, download, and delete legal hold data without proper authorization. The vulnerability is identified by Mattermost Advisory ID MMSA-2026-00621 and poses a significant risk to organizations using the affected plugin versions, potentially leading to data breaches and compliance violations.

## Attack Chain

1.  Attacker authenticates to the Mattermost server with valid user credentials.
2.  Attacker crafts a malicious API request targeting the Legal Hold plugin's endpoints.
3.  The request is sent to the Mattermost server.
4.  The ServeHTTP function in the Legal Hold plugin processes the request.
5.  Authorization check fails due to insufficient privileges or incorrect parameters.
6.  Instead of halting request processing, the plugin continues to execute the request.
7.  The attacker gains unauthorized access to legal hold data or performs unauthorized actions (create, download, delete).
8.  The attacker successfully exfiltrates or manipulates sensitive legal hold information.

## Impact

Successful exploitation of this vulnerability (CVE-2026-3524) allows authenticated attackers to bypass authorization controls within the Mattermost Legal Hold plugin. This can result in unauthorized access, creation, modification, or deletion of sensitive legal hold data. The vulnerability affects versions 1.1.4 and earlier of the plugin. Organizations using the affected versions are at risk of data breaches, compliance violations, and reputational damage. A CVSS v3.1 score of 8.8 indicates a high level of severity due to the potential for significant data compromise.

## Recommendation

*   Upgrade the Mattermost Legal Hold plugin to a version later than 1.1.4 to remediate CVE-2026-3524.
*   Deploy the Sigma rules provided in this brief to detect exploitation attempts targeting the vulnerable Legal Hold plugin endpoints (see rules section).
*   Monitor Mattermost server logs for unusual API requests to the Legal Hold plugin, specifically those resulting in unexpected data access or modification, as a potential sign of exploitation (webserver log source).
