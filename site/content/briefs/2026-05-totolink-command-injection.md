---
title: Totolink A8000RU OS Command Injection via Web Management Interface
slug: 2026-05-totolink-command-injection
description: A remote command injection vulnerability exists in the UploadOpenVpnCert function of the Totolink A8000RU version 7.1cu.643_b20200521 web management interface due to improper neutralization of the FileName argument, allowing unauthenticated attackers to execute arbitrary OS commands.
date: "2026-05-26T14:02:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - router
  - web-management
  - cve
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-9455
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9455
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_342/README.md
  - https://vuldb.com/submit/813449
  - https://vuldb.com/vuln/365436
  - https://vuldb.com/vuln/365436/cti
  - https://www.totolink.net/
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt
    description: Detects attempts to exploit command injection in Totolink A8000RU routers by looking for suspicious characters in the FileName parameter of requests to cstecgi.cgi
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9455 Command Injection in Totolink Web Interface
    description: Detects CVE-2026-9455 exploitation —  HTTP POST requests to /cgi-bin/cstecgi.cgi with shell metacharacters in the FileName parameter indicating a command injection attempt against the UploadOpenVpnCert function.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Outbound Network Connection from Totolink Router
    description: Detects outbound network connections from Totolink routers that may indicate a compromised device.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

A critical vulnerability, identified as CVE-2026-9455, affects Totolink A8000RU routers running firmware version 7.1cu.643_b20200521. The vulnerability resides within the web management interface, specifically in the `UploadOpenVpnCert` function accessible via `/cgi-bin/cstecgi.cgi`. An attacker can inject arbitrary OS commands by manipulating the `FileName` argument during the OpenVPN certificate upload process. The vulnerability is remotely exploitable without authentication, and a public exploit is available, increasing the risk of widespread exploitation. This poses a significant threat to affected devices, potentially leading to full system compromise.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP request to `/cgi-bin/cstecgi.cgi`.
2. The request targets the `UploadOpenVpnCert` function.
3. The attacker manipulates the `FileName` parameter in the HTTP request.
4. The manipulated `FileName` contains OS command injection payload (e.g., using shell metacharacters like `;`, `|`, or `&&`).
5. The web management interface processes the request without proper sanitization of the `FileName`.
6. The injected OS command is executed by the system with the privileges of the web server process.
7. The attacker gains arbitrary code execution on the router.
8. The attacker can then use this foothold to pivot further into the network or cause a denial of service.

## Impact

Successful exploitation of CVE-2026-9455 allows unauthenticated attackers to execute arbitrary commands on the affected Totolink A8000RU router. This could lead to a complete compromise of the device, allowing attackers to steal sensitive information, modify router configurations, intercept network traffic, or use the device as a bot in a botnet. Given the availability of a public exploit, mass exploitation is possible, potentially impacting a large number of home and small business networks relying on these routers.

## Recommendation

*   Monitor web server logs for POST requests to `/cgi-bin/cstecgi.cgi` with shell metacharacters in the `FileName` parameter using the Sigma rule "Detect Totolink A8000RU Command Injection Attempt".
*   Apply the Sigma rule "Detect CVE-2026-9455 Command Injection in Totolink Web Interface" to identify command injection attempts based on common exploit patterns.
*   Due to the lack of available patch information from the vendor, consider network segmentation to limit the impact of a successful compromise and place the device on an isolated VLAN.
*   Monitor network traffic for suspicious outbound connections originating from Totolink routers using the Sigma rule "Detect Outbound Network Connection from Totolink Router".
