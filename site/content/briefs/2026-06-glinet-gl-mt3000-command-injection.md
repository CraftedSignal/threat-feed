---
brief_id: brief-2026-06-glinet-gl-mt3000-command-injection
event_id: brief-2026-06-glinet-gl-mt3000-command-injection
revision: 1
activity_at: "2026-06-14T23:25:50Z"
title: 'CVE-2026-11452: GL.iNet GL-MT3000 Command Injection Vulnerability'
slug: 2026-06-glinet-gl-mt3000-command-injection
description: A command injection vulnerability (CVE-2026-11452) has been discovered in GL.iNet GL-MT3000 routers running firmware versions up to 4.4.5, allowing remote attackers to execute arbitrary commands by manipulating the 'Password' argument in the '/cgi-bin/glc' endpoint.
date: "2026-06-14T23:25:50Z"
lastmod: "2026-10-30T03:31:26Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:gl_inet:gl_mt3000_4_4_5:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HUNT-BENITO-GLINET-BERYL-AX-TRIPLE-RCE-CVE-2026-11450-11451-11452-UNAUTHENTICATED-ROOT-ON-TRAVEL-ROUTER&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - command-injection
  - router
  - network
vendors:
  - GL.iNet
products:
  - GL-MT3000 <= 4.4.5 (<= 4.4.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
cves:
  - id: CVE-2026-11452
    cvss: 7.3
    epss: 0.01681
    kev_status: "false"
  - id: CVE-2026-11450
    cvss: 7.3
    epss: 0.01572
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11452
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HUNT-BENITO-GLINET-BERYL-AX-TRIPLE-RCE-CVE-2026-11450-11451-11452-UNAUTHENTICATED-ROOT-ON-TRAVEL-ROUTER&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-11452 Exploitation - GL.iNet GL-MT3000 Command Injection Attempt
    description: Detects CVE-2026-11452 exploitation - HTTP POST requests to '/cgi-bin/glc' with command injection payloads in the 'Password' parameter, targeting GL.iNet GL-MT3000 routers.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-10-30T03:31:26Z"
    level: L2
    summary: poc_available; added CVE-2026-11450; gl-mt3000 <= 4.4.5 version <= 4.4.5
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HUNT-BENITO-GLINET-BERYL-AX-TRIPLE-RCE-CVE-2026-11450-11451-11452-UNAUTHENTICATED-ROOT-ON-TRAVEL-ROUTER&utm_source=rss&utm_medium=rss
---

A critical command injection vulnerability, tracked as CVE-2026-11452, has been identified in GL.iNet GL-MT3000 routers running firmware versions up to 4.4.5. The flaw resides within the `SET_USER_PWD Handler` function (specifically FUN_0042e200) located in the `/cgi-bin/glc` file. This vulnerability allows an unauthenticated remote attacker to execute arbitrary operating system commands on the affected router by submitting a specially crafted `Password` argument. This manipulation bypasses intended security controls, leading to full compromise of the device. Successful exploitation could result in unauthorized network access, interception of network traffic, router configuration modification, or the inclusion of the device in a botnet. Upgrading to firmware version 4.8.1 or later is required to address this critical issue and prevent remote exploitation.

## Attack Chain

1.  An attacker identifies a GL.iNet GL-MT3000 router running a vulnerable firmware version (up to 4.4.5) that is accessible remotely.
2.  The attacker crafts a malicious HTTP POST request targeting the `/cgi-bin/glc` endpoint on the vulnerable router.
3.  The request includes a specially formed `Password` argument containing shell metacharacters (e.g., `;`, `|`, `$(`, `` ` ``) designed for command injection.
4.  The vulnerable `SET_USER_PWD Handler` function (FUN_0042e200) within the router's firmware processes this unvalidated `Password` argument.
5.  The embedded shell metacharacters are interpreted and executed by the underlying operating system shell, leading to remote command injection.
6.  The attacker successfully executes arbitrary commands on the router, potentially establishing a reverse shell or downloading additional malware.
7.  The attacker proceeds to gain full control over the router, allowing them to modify network settings, intercept traffic, or use the device as a pivot point for further network compromise.
8.  This allows for network compromise, data exfiltration, or the establishment of a persistent foothold within the victim's network.

## Impact

Successful exploitation of CVE-2026-11452 grants remote attackers full control over the affected GL.iNet GL-MT3000 router. The impact includes unauthorized access to the network segment the router controls, potential for data interception, modification of DNS settings to redirect users to malicious sites, or the installation of persistent backdoors. Compromised routers can be leveraged as part of botnets for DDoS attacks or as proxies for other malicious activities, significantly degrading network performance and security. The broad deployment of such devices makes them attractive targets for attackers seeking initial access to home or small business networks.

## Recommendation

*   Immediately upgrade all GL.iNet GL-MT3000 routers to firmware version 4.8.1 or later to mitigate CVE-2026-11452.
*   Deploy the provided Sigma rule to your SIEM solution to detect exploitation attempts against the `/cgi-bin/glc` endpoint.
*   Enable comprehensive web server logging for all internet-facing devices, specifically monitoring requests to `/cgi-bin/glc` for suspicious `cs-uri-query` patterns.
