---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-5851)
slug: 2026-04-totolink-cmd-injection
description: A remote command injection vulnerability (CVE-2026-5851) exists in the Totolink A7100RU router version 7.4cu.2313_b20191024 via manipulation of the 'enable' argument in the setUPnPCfg function within the /cgi-bin/cstecgi.cgi CGI handler, potentially leading to arbitrary code execution.
date: "2026-04-09T06:16:23Z"
severities:
  - critical
tags:
  - cve-2026-5851
  - command-injection
  - totolink
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5851
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5851
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_157/README.md
  - https://vuldb.com/submit/791271
  - https://vuldb.com/vuln/356377
  - https://vuldb.com/vuln/356377/cti
  - https://www.totolink.net/
rules:
  - title: Detect Suspicious Totolink CGI Requests
    description: Detects requests to the cstecgi.cgi endpoint with suspicious parameters indicative of command injection attempts targeting CVE-2026-5851
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink Reboot Command
    description: Detects reboot commands executed by the webserver, potentially indicating exploitation of CVE-2026-5851
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-5851, has been identified in the Totolink A7100RU router, specifically version 7.4cu.2313_b20191024. This flaw resides within the CGI handler component, affecting the `setUPnPCfg` function within the `/cgi-bin/cstecgi.cgi` file. The vulnerability allows for OS command injection through manipulation of the `enable` argument. Given that the exploit has been publicly released, it poses a significant risk to unpatched devices, potentially leading to complete system compromise. This is especially concerning as routers are often exposed to the internet and are attractive targets for botnet recruitment, data theft, or establishing a foothold within a network.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A7100RU router running firmware version 7.4cu.2313_b20191024.
2.  The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  Within the HTTP request, the attacker manipulates the `enable` argument passed to the `setUPnPCfg` function.
4.  The injected payload contains OS commands, leveraging the command injection vulnerability.
5.  The vulnerable `setUPnPCfg` function executes the injected OS commands with elevated privileges.
6.  The attacker gains remote code execution on the router's operating system.
7.  The attacker may then install malware, change DNS settings, or use the router as a proxy for further attacks.

## Impact

Successful exploitation of CVE-2026-5851 allows an unauthenticated remote attacker to execute arbitrary commands on the affected Totolink A7100RU router. This could lead to complete compromise of the device, potentially enabling attackers to gain access to the local network, steal sensitive information, or use the router as part of a botnet. Given the ease of exploitation and the widespread use of vulnerable routers, this poses a significant risk to home and small business networks.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious Totolink CGI Requests` to identify attempts to exploit the command injection vulnerability in web server logs.
*   Apply any available firmware updates from Totolink to patch CVE-2026-5851.
*   Monitor network traffic for unusual outbound connections originating from Totolink A7100RU devices.
*   Implement network segmentation to limit the impact of a compromised router on the rest of the network.
