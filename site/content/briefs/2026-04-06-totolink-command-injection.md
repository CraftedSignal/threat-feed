---
brief_id: brief-2026-04-06-totolink-command-injection
event_id: brief-2026-04-06-totolink-command-injection
revision: 2
activity_at: "2026-04-06T23:16:30Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:936d6651b9a1a233d2ca57f282960e162a11a808233d499df51b864e11ea38be
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Totolink A7100RU Command Injection Vulnerability
slug: 2026-04-06-totolink-command-injection
description: A command injection vulnerability exists in Totolink A7100RU firmware version 7.4cu.2313_b20191024, allowing remote attackers to execute arbitrary OS commands by manipulating the 'tz' argument in the setNtpCfg function within the /cgi-bin/cstecgi.cgi file.
date: "2026-04-06T23:16:30Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - command-injection
  - router
  - totolink
  - cve-2026-5689
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5689
    cvss: 7.3
    epss: 0.01459
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5689
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_187/README.md
  - https://vuldb.com/vuln/355516
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects attempts to exploit the command injection vulnerability (CVE-2026-5689) in Totolink A7100RU via crafted HTTP requests to cstecgi.cgi
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Post Exploitation Activity
    description: Detects suspicious network connections originating from Totolink A7100RU devices after potential command injection exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-5689, affects Totolink A7100RU devices running firmware version 7.4cu.2313_b20191024. The vulnerability is located within the `setNtpCfg` function of the `/cgi-bin/cstecgi.cgi` file. An attacker can exploit this flaw by manipulating the `tz` argument, injecting and executing arbitrary operating system commands. Given that a public exploit is available, unpatched Totolink A7100RU devices are at high risk of compromise. This vulnerability allows unauthenticated remote attackers to gain unauthorized access and control over the affected device.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP POST request to `/cgi-bin/cstecgi.cgi`.
2. The request targets the `setNtpCfg` function.
3. The attacker injects malicious OS commands within the `tz` parameter of the HTTP POST request.
4. The `setNtpCfg` function processes the request without proper sanitization of the `tz` parameter.
5. The injected OS commands are executed with the privileges of the web server process.
6. The attacker gains remote code execution on the device.
7. The attacker may then install persistent backdoors or malware to maintain access.
8. The attacker can pivot to other devices on the network, exfiltrate sensitive data, or use the compromised device as part of a botnet.

## Impact

Successful exploitation of CVE-2026-5689 allows a remote, unauthenticated attacker to execute arbitrary commands on the affected Totolink A7100RU device. This could lead to complete compromise of the router, allowing the attacker to control network traffic, access sensitive data stored on connected devices, or use the router as a launchpad for further attacks within the network. Given the widespread use of these routers in homes and small businesses, a successful attack could have a significant impact.

## Recommendation

*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` with unusual parameters in the query string, and deploy the Sigma rule `Detect Totolink A7100RU Command Injection Attempt` to detect exploitation attempts.
*   Inspect network traffic for command execution patterns originating from the router's IP address, correlating them with requests to the `/cgi-bin/cstecgi.cgi` endpoint using the `Detect Totolink A7100RU Post Exploitation Activity` rule.
*   Apply the latest firmware updates from Totolink as soon as they become available to patch CVE-2026-5689 (if a patch becomes available).
