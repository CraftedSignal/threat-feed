---
title: Neko Authenticated User Privilege Escalation (CVE-2026-39386)
slug: 2024-01-neko-privesc
description: An authenticated user can escalate privileges to full administrative control in Neko versions 3.0.0 through 3.0.10 and 3.1.0 through 3.1.1 due to CVE-2026-39386, leading to complete compromise of the instance.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - neko
  - privilege-escalation
  - CVE-2026-39386
  - linux
vendors:
  - Neko
products:
  - Neko
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-39386
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39386
rules:
  - title: Detect Access to Sensitive Neko API Endpoint
    description: Detects access to the /api/profile endpoint which is implicated in CVE-2026-39386
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Failed POST Requests to Neko API Endpoint
    description: Detects multiple failed POST requests to the /api/profile endpoint, possibly indicating attempted exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Neko is a self-hosted virtual browser that runs in Docker and utilizes WebRTC. Versions 3.0.0 through 3.0.10 and 3.1.0 through 3.1.1 contain a critical vulnerability (CVE-2026-39386) that allows any authenticated user to immediately gain full administrative control over the entire Neko instance. This includes member management, room settings, broadcast control, and session termination. Successful exploitation results in a complete compromise of the affected Neko instance, potentially exposing sensitive data and allowing unauthorized actions. This vulnerability has been patched in versions 3.0.11 and 3.1.2. Defenders should prioritize upgrading vulnerable instances immediately.

## Attack Chain

1.  Attacker authenticates to the Neko instance using valid user credentials.
2.  Attacker sends a crafted API request to the `/api/profile` endpoint (if enabled).
3.  The vulnerable code in Neko processes the request without proper authorization checks.
4.  The attacker leverages the vulnerability to modify their user role or other administrative settings.
5.  The attacker gains administrative privileges within the Neko instance.
6.  Attacker manipulates member management, room settings, broadcast controls, or terminates sessions.
7.  The attacker can exfiltrate data, modify system configurations, or disrupt services.
8.  The attacker achieves full control of the Neko instance, compromising all hosted browsing sessions.

## Impact

Successful exploitation of CVE-2026-39386 allows any authenticated user to gain complete administrative control over the Neko instance. This can lead to unauthorized access to browsing sessions, data exfiltration, modification of system configurations, and disruption of services. The impact is significant, potentially affecting any organization utilizing Neko for secure or isolated browsing. The number of victims will depend on the number of Neko instances exposed and the number of internal users with access to Neko.

## Recommendation

*   Upgrade Neko instances to version 3.0.11 or 3.1.2 to patch CVE-2026-39386 immediately.
*   Restrict access to the `/api/profile` endpoint, if feasible, as a temporary mitigation.
*   Deploy the Sigma rules provided to detect attempts to exploit this vulnerability in Neko webserver logs.
*   Monitor Neko instance logs for suspicious privilege changes or unexpected administrative actions.
*   Place the Neko instance behind authentication layers, such as a reverse proxy with additional access controls.
