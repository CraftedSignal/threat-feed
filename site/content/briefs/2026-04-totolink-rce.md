---
title: Totolink A7100RU OS Command Injection via setTelnetCfg
slug: 2026-04-totolink-rce
description: CVE-2026-5994 describes a critical OS command injection vulnerability in the Totolink A7100RU router (version 7.4cu.2313_b20191024) allowing remote attackers to execute arbitrary commands by manipulating the 'telnet_enabled' argument in the /cgi-bin/cstecgi.cgi CGI handler, with a public exploit available.
date: "2026-04-10T01:19:14Z"
severities:
  - critical
tags:
  - cve-2026-5994
  - command-injection
  - totolink
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5994
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5994
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_166/README.md
  - https://vuldb.com/vuln/356548
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects attempts to exploit the command injection vulnerability (CVE-2026-5994) in Totolink A7100RU routers by monitoring requests to the /cgi-bin/cstecgi.cgi endpoint with suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Telnet Enable Command Injection
    description: Detects command injection attempts via the telnet_enabled parameter targeting Totolink A7100RU routers, focusing on common command injection payloads.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, identified as CVE-2026-5994, exists in the Totolink A7100RU router, specifically version 7.4cu.2313_b20191024. The flaw lies within the `setTelnetCfg` function of the `/cgi-bin/cstecgi.cgi` CGI handler. By manipulating the `telnet_enabled` argument, a remote attacker can inject and execute arbitrary operating system commands on the device. This vulnerability allows unauthenticated attackers to gain full control of the affected router. The existence of a publicly available exploit increases the likelihood of widespread exploitation. This vulnerability poses a significant risk to users of this router model, potentially enabling attackers to compromise their network and data.

## Attack Chain

1.  Attacker identifies a vulnerable Totolink A7100RU router with firmware version 7.4cu.2313_b20191024 exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The HTTP request includes a modified `telnet_enabled` parameter designed to inject OS commands.
4.  The `setTelnetCfg` function processes the injected OS command without proper sanitization.
5.  The injected command is executed by the operating system with the privileges of the web server process.
6.  The attacker gains remote code execution on the router.
7.  The attacker may install malware, modify router configurations, or use the compromised device as a botnet node.

## Impact

Successful exploitation of CVE-2026-5994 allows a remote attacker to execute arbitrary operating system commands on the affected Totolink A7100RU router. This can lead to a complete compromise of the device, potentially impacting all connected devices on the network. Attackers could potentially exfiltrate sensitive data, install malicious firmware, or use the router as part of a botnet. Given the critical severity and public exploit availability, widespread exploitation is likely, potentially affecting thousands of users.

## Recommendation

*   Deploy the Sigma rule `Detect Totolink A7100RU Command Injection Attempt` to identify exploitation attempts targeting `/cgi-bin/cstecgi.cgi` (see rule below).
*   Apply available patches or firmware updates from Totolink to address CVE-2026-5994.
*   If patching is not immediately possible, restrict access to the router's web interface from the public internet using firewall rules.
