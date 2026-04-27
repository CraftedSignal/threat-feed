---
title: Signal K Server Unauthenticated Privilege Escalation (CVE-2026-33950)
slug: 2026-04-signalk-privesc
description: An unauthenticated attacker can achieve full administrator access on vulnerable Signal K Servers by injecting an admin role via the /enableSecurity endpoint, allowing modification of sensitive vessel data and server configuration.
date: "2026-04-02T17:16:22Z"
severities:
  - critical
tags:
  - cve-2026-33950
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-33950
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33950
  - https://github.com/SignalK/signalk-server/releases/tag/v2.24.0-beta.4
  - https://github.com/SignalK/signalk-server/security/advisories/GHSA-x8hc-fqv3-7gwf
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Unauthorized Access to Signal K /enableSecurity Endpoint
    description: Detects unauthorized POST requests to the /enableSecurity endpoint, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Sensitive SignalK Endpoints After Potential PrivEsc
    description: Detects access to sensitive endpoints, such as those modifying vessel data or server configuration, potentially indicating attacker activity following successful privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Signal K Server is a server application used on boats for central hub management. Versions prior to 2.24.0-beta.4 are vulnerable to privilege escalation (CVE-2026-33950). An unauthenticated attacker can gain full Administrator access to the SignalK server by exploiting Admin Role Injection via the `/enableSecurity` endpoint. This vulnerability allows attackers to modify sensitive vessel routing data, alter server configurations, and access restricted endpoints without authentication. The…
