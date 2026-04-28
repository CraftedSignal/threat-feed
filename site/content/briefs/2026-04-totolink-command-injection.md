---
title: Totolink A7100RU Command Injection Vulnerability (CVE-2026-5691)
slug: 2026-04-totolink-command-injection
description: A remote command injection vulnerability affects Totolink A7100RU version 7.4cu.2313_b20191024 allowing unauthenticated attackers to execute arbitrary commands on the device via the setFirewallType function.
date: "2026-04-06T23:16:32Z"
severities:
  - critical
tags:
  - command-injection
  - totolink
  - cve-2026-5691
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5691
    cvss: 7.3
    epss: 0.03903
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5691
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_189/README.md
  - https://vuldb.com/vuln/355518
rules:
  - title: Detect Totolink Command Injection Attempt via firewallType
    description: Detects potential command injection attempts targeting the Totolink A7100RU setFirewallType function by looking for suspicious characters or commands in the firewallType parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect POST to cstecgi.cgi with Common Command Injection Payloads
    description: Detects POST requests to cstecgi.cgi containing common command injection payloads.
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

A critical command injection vulnerability, CVE-2026-5691, has been identified in Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability resides within the `setFirewallType` function of the `/cgi-bin/cstecgi.cgi` script. A remote, unauthenticated attacker can exploit this flaw by manipulating the `firewallType` argument to inject and execute arbitrary operating system commands on the vulnerable device. Publicly available exploits exist, increasing the urgency for patching or mitigating this vulnerability. Successful exploitation grants the attacker complete control over the affected router, potentially leading to data theft, network disruption, or further malicious activity within the network.

## Attack Chain

1. The attacker identifies a vulnerable Totolink A7100RU router running firmware version 7.4cu.2313_b20191024.
2. The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3. The attacker injects a payload containing OS commands into the `firewallType` argument of the HTTP request.
4. The vulnerable `setFirewallType` function processes the attacker-supplied input without proper sanitization.
5. The injected OS commands are executed by the router's operating system.
6. The attacker gains remote code execution on the router, allowing them to perform arbitrary actions.
7. The attacker may establish a reverse shell or download malicious binaries to the router's file system.
8. The attacker can pivot into the internal network, compromise other devices, or use the router as a bot in a botnet.

## Impact

Successful exploitation of CVE-2026-5691 grants attackers full control over the vulnerable Totolink A7100RU router. This can lead to a variety of malicious outcomes, including data exfiltration, denial of service, and lateral movement within the compromised network. Given the widespread use of Totolink routers, a significant number of devices are potentially vulnerable. Compromised routers can be leveraged to launch attacks against other network devices, steal sensitive information, or disrupt network services.

## Recommendation

*   Apply available firmware updates from Totolink to patch CVE-2026-5691.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with unusual values in the `firewallType` parameter to detect exploitation attempts (see Sigma rule below).
*   Implement network segmentation to limit the impact of a compromised router on other network devices.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
