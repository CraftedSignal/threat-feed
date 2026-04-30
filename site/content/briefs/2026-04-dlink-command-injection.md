---
title: D-Link DIR-882 Remote Command Injection Vulnerability (CVE-2026-5844)
slug: 2026-04-dlink-command-injection
description: A command injection vulnerability (CVE-2026-5844) exists in the D-Link DIR-882 router version 1.01B02, allowing a remote attacker to execute arbitrary OS commands by manipulating the IPAddress argument in the HNAP1 SetNetworkSettings Handler via the prog.cgi script.
date: "2026-04-09T05:16:06Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - command-injection
  - d-link
  - router
  - cve-2026-5844
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5844
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5844
  - https://files.catbox.moe/ei31k1.zip
  - https://vuldb.com/vuln/356329
iocs:
  - type: url
    value: https://files.catbox.moe/ei31k1.zip
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect D-Link DIR-882 Command Injection Attempt
    description: Detects potential command injection attempts targeting the D-Link DIR-882 router via the prog.cgi script by looking for shell metacharacters in the IPAddress parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: D-Link DIR-882 Suspicious POST Request to prog.cgi
    description: Detects suspicious POST requests to prog.cgi, which may indicate exploitation attempts against D-Link DIR-882 routers.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5844 describes a critical command injection vulnerability affecting D-Link DIR-882 routers running firmware version 1.01B02. The vulnerability resides in the `sprintf` function within the `prog.cgi` script, specifically within the HNAP1 SetNetworkSettings Handler. A remote, unauthenticated attacker can exploit this flaw by manipulating the `IPAddress` argument, injecting arbitrary OS commands that are then executed with elevated privileges. The vulnerability is considered critical due to the potential for complete system compromise and the availability of a public exploit. This vulnerability impacts products that are no longer supported by the maintainer, increasing the risk for users who have not migrated to newer devices.

## Attack Chain

1.  The attacker identifies a vulnerable D-Link DIR-882 router running firmware version 1.01B02.
2.  The attacker sends a crafted HTTP request to the `prog.cgi` endpoint.
3.  The HTTP request targets the HNAP1 SetNetworkSettings Handler.
4.  The attacker manipulates the `IPAddress` argument within the HTTP request, injecting malicious OS commands.
5.  The `sprintf` function in `prog.cgi` processes the attacker-controlled `IPAddress` argument without proper sanitization.
6.  The injected OS commands are executed on the router's operating system due to the command injection vulnerability in `sprintf`.
7.  The attacker gains remote code execution on the router.
8.  The attacker can then perform actions such as modifying router settings, eavesdropping on network traffic, or using the router as a botnet node.

## Impact

Successful exploitation of CVE-2026-5844 allows a remote attacker to execute arbitrary OS commands on the vulnerable D-Link DIR-882 router. This can lead to a complete compromise of the device, enabling attackers to reconfigure the router, intercept network traffic, or use the compromised device as part of a botnet. The vulnerability affects end-of-life products, meaning no official patches are available. The impact is significant due to the widespread use of these routers in home and small business networks, where they can act as a gateway to internal systems.

## Recommendation

*   Deploy the Sigma rule `Detect D-Link DIR-882 Command Injection Attempt` to detect suspicious requests to `prog.cgi` containing shell metacharacters.
*   Block access to the URL `https://files.catbox.moe/ei31k1.zip` to prevent the download of the publicly available exploit (IOC).
*   Monitor web server logs for HTTP requests to `prog.cgi` with unusually long `IPAddress` parameters (log source: webserver).
*   Implement network intrusion detection systems (IDS) rules to identify and block exploit attempts targeting CVE-2026-5844 (log source: network_connection).
