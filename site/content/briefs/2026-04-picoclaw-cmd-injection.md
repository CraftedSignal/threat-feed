---
title: PicoClaw Web Launcher Management Plane Command Injection Vulnerability
slug: 2026-04-picoclaw-cmd-injection
description: PicoClaw version 0.2.4 is vulnerable to command injection via the /api/gateway/restart endpoint of the Web Launcher Management Plane, allowing a remote attacker to execute arbitrary commands by manipulating input.
date: "2026-04-25T17:16:33Z"
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - web-application
vendors:
  - sipeed
products:
  - PicoClaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-6987
    cvss: 7.3
    epss: 0.01021
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6987
  - https://github.com/sipeed/picoclaw/issues/2307
  - https://vuldb.com/vuln/359530
rules:
  - title: Detect Suspicious PicoClaw Restart Requests
    description: Detects suspicious requests to the /api/gateway/restart endpoint in PicoClaw which may indicate a command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Command Injection Characters in URI
    description: Detects common command injection characters in URI requests.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A command injection vulnerability exists in PicoClaw version 0.2.4, specifically affecting the `/api/gateway/restart` endpoint within the Web Launcher Management Plane component. This flaw allows unauthenticated remote attackers to inject and execute arbitrary commands on the underlying system. The vulnerability, identified as CVE-2026-6987, stems from improper neutralization of special elements in the input to the `/api/gateway/restart` function. The project maintainers were notified through…
