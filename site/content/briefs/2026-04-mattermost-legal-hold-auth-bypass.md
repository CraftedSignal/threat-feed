---
title: Mattermost Legal Hold Plugin Authentication Bypass Vulnerability
slug: 2026-04-mattermost-legal-hold-auth-bypass
description: Mattermost Legal Hold plugin versions 1.1.4 and earlier allow authenticated attackers to bypass authorization checks, enabling unauthorized access and modification of legal hold data via crafted API requests.
date: "2026-04-06T13:17:18Z"
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

The Mattermost Legal Hold plugin, in versions 1.1.4 and earlier, contains an authentication bypass vulnerability (CVE-2026-3524) that can be exploited by authenticated attackers. The vulnerability lies in the ServeHTTP function, where a failed authorization check does not properly halt request processing. This flaw allows attackers to craft malicious API requests to the plugin's endpoints, enabling them to access, create, download, and delete legal hold data without proper authorization. The…
