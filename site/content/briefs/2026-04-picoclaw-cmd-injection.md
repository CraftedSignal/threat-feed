---
title: PicoClaw Web Launcher Management Plane Command Injection Vulnerability
slug: 2026-04-picoclaw-cmd-injection
description: PicoClaw version 0.2.4 is vulnerable to command injection via the /api/gateway/restart endpoint of the Web Launcher Management Plane, allowing a remote attacker to execute arbitrary commands by manipulating input.
date: "2026-04-25T17:16:33Z"
type: advisory
types:
  - advisory
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

A command injection vulnerability exists in PicoClaw version 0.2.4, specifically affecting the `/api/gateway/restart` endpoint within the Web Launcher Management Plane component. This flaw allows unauthenticated remote attackers to inject and execute arbitrary commands on the underlying system. The vulnerability, identified as CVE-2026-6987, stems from improper neutralization of special elements in the input to the `/api/gateway/restart` function. The project maintainers were notified through an issue report, but as of the time of disclosure, no response or patch has been released. This vulnerability poses a significant risk, potentially leading to full system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable PicoClaw instance running version 0.2.4.
2.  The attacker crafts a malicious HTTP request targeting the `/api/gateway/restart` endpoint.
3.  Within the request, the attacker injects OS commands into a parameter processed by the vulnerable function.
4.  The PicoClaw application fails to properly sanitize the attacker-supplied input.
5.  The application executes the injected commands with the privileges of the web server process.
6.  The attacker gains arbitrary code execution on the server.
7.  The attacker uses the initial foothold to escalate privileges, potentially gaining root access.
8.  The attacker installs malware, exfiltrates sensitive data, or performs other malicious activities.

## Impact

Successful exploitation of this command injection vulnerability allows a remote attacker to execute arbitrary commands on the affected system. This could lead to complete system compromise, data theft, or denial of service. Given the nature of command injection, the attacker may be able to escalate privileges and gain full control over the server. The number of potential victims is unknown, but any PicoClaw installation running version 0.2.4 exposed to the network is at risk.

## Recommendation

*   Apply available patches for PicoClaw as soon as they are released to remediate CVE-2026-6987.
*   Implement input validation and sanitization on the `/api/gateway/restart` endpoint to prevent command injection.
*   Deploy the Sigma rule `Detect Suspicious PicoClaw Restart Requests` to monitor for exploitation attempts.
*   Monitor web server logs for unusual activity or suspicious commands executed via HTTP requests, correlating with requests to `/api/gateway/restart`.
*   Consider using a web application firewall (WAF) to filter malicious requests targeting the `/api/gateway/restart` endpoint.
