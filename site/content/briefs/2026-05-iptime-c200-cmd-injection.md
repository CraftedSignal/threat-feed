---
title: EFM ipTIME C200 Command Injection Vulnerability
slug: 2026-05-iptime-c200-cmd-injection
description: EFM ipTIME C200 devices are vulnerable to remote command injection due to insufficient validation of the RestoreFile argument in the /cgi/iux_set.cgi endpoint, allowing attackers to execute arbitrary commands with elevated privileges.
date: "2026-05-05T13:16:31Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - command injection
  - iot
  - cve-2026-7833
vendors:
  - EFM
products:
  - ipTIME C200
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-7833
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7833
  - https://github.com/glkfc/IoT-Vulnerability/blob/main/iptime/c200/sub_409054_vulnerability_report_EN.md
  - https://vuldb.com/vuln/361112
rules:
  - title: Detect Command Injection Attempts via RestoreFile Argument
    description: Detects potential command injection attempts by monitoring POST requests to the /cgi/iux_set.cgi endpoint with suspicious characters in the RestoreFile argument.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect access to iux_set.cgi
    description: Detects access to /cgi/iux_set.cgi which could be related to exploitation of CVE-2026-7833.
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

A critical command injection vulnerability, CVE-2026-7833, affects EFM ipTIME C200 devices up to version 1.092. The vulnerability resides within the `sub_408F90` function of the `/cgi/iux_set.cgi` file, specifically the ApplyRestore Endpoint. By manipulating the `RestoreFile` argument, an attacker can inject arbitrary commands that will be executed on the device. The vulnerability can be exploited remotely and proof-of-concept exploit code is publicly available. The vendor was notified but did not respond, increasing the risk to users of these devices. This vulnerability allows for complete system compromise of affected devices.

## Attack Chain

1. The attacker sends a crafted HTTP POST request to `/cgi/iux_set.cgi`.
2. The request includes the `RestoreFile` argument containing a command injection payload within the `ApplyRestore` endpoint.
3. The `sub_408F90` function processes the `RestoreFile` argument without proper sanitization.
4. The injected command is executed with the privileges of the webserver process.
5. The attacker gains arbitrary code execution on the device.
6. The attacker pivots to internal network if the device acts as a gateway.
7. The attacker may install persistent backdoors or malware.
8. The attacker could exfiltrate sensitive information or disrupt device operations.

## Impact

Successful exploitation of CVE-2026-7833 allows a remote attacker to execute arbitrary commands on the EFM ipTIME C200 device. This could lead to complete compromise of the device, including unauthorized access to the device's configuration, data, and network. Given the device's role as a network gateway, successful exploitation could also allow the attacker to pivot to other devices on the internal network. The lack of vendor response exacerbates the risk.

## Recommendation

*   Apply network access control lists to restrict access to the `/cgi/iux_set.cgi` endpoint from untrusted networks.
*   Monitor web server logs for suspicious POST requests targeting the `/cgi/iux_set.cgi` endpoint with unusual `RestoreFile` arguments. Deploy the Sigma rule to detect command injection attempts.
*   Utilize vulnerability scanning tools to identify potentially vulnerable EFM ipTIME C200 devices on the network.
