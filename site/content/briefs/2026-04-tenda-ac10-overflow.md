---
title: Tenda AC10 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-ac10-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5550) in Tenda AC10 firmware version 16.03.10.10_multi_TDE01 within the /bin/httpd SysToolChangePwd function allows remote attackers to execute arbitrary code.
date: "2026-04-05T08:16:25Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-5550
  - tenda
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5550
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5550
  - https://github.com/somanyerrors/tenda-ac10v4-vulnerabilities/blob/main/findings/HIGH-01-getvalue-229-callers.md
  - https://vuldb.com/vuln/355314
rules:
  - title: Detect Tenda AC10 HTTPD Buffer Overflow Attempt
    description: Detects potential attempts to exploit the CVE-2026-5550 buffer overflow vulnerability in Tenda AC10 routers by monitoring HTTP POST requests to /bin/httpd with excessive parameter lengths.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda AC10 HTTPD Access
    description: Detects access to the /bin/httpd endpoint on Tenda AC10 routers.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-5550, exists in Tenda AC10 router firmware version 16.03.10.10_multi_TDE01. The vulnerability is located in the `fromSysToolChangePwd` function within the `/bin/httpd` binary. A remote attacker can exploit this flaw to overwrite the stack and potentially execute arbitrary code on the affected device. This is achieved by sending a specially crafted request to the device. Successful exploitation could lead to complete system compromise, allowing attackers to gain unauthorized access, control the device, or use it as a foothold for further network intrusion. Given the widespread use of Tenda routers, this vulnerability poses a significant risk to home and small business networks.

## Attack Chain

1. The attacker identifies a Tenda AC10 router running firmware version 16.03.10.10_multi_TDE01.
2. The attacker crafts a malicious HTTP request targeting the `/bin/httpd` endpoint.
3. The malicious request is designed to overflow the buffer in the `fromSysToolChangePwd` function when processing the request parameters.
4. The overflow overwrites the stack with attacker-controlled data, including the return address.
5. The `httpd` process attempts to return from the `fromSysToolChangePwd` function.
6. Due to the overwritten return address, execution is redirected to the attacker's code.
7. The attacker's code executes with the privileges of the `httpd` process.
8. The attacker gains control of the device and can perform arbitrary actions, such as modifying router settings, executing commands, or establishing a backdoor.

## Impact

Successful exploitation of CVE-2026-5550 allows a remote attacker to gain complete control of the affected Tenda AC10 router. This can lead to data breaches, denial-of-service attacks, or the router being used as part of a botnet. Given the potential for widespread exploitation and the ease with which the vulnerability can be triggered, CVE-2026-5550 poses a high risk to users of the affected Tenda AC10 router model. The attacker could potentially monitor all network traffic passing through the device, steal sensitive information, or use the compromised device to launch attacks against other systems on the network or the internet.

## Recommendation

*   Monitor web server logs for suspicious POST requests to `/bin/httpd` with abnormally large parameter values that could indicate a buffer overflow attempt targeting the `fromSysToolChangePwd` function to trigger the vulnerability (see the related Sigma rule below).
*   Since a patch is not mentioned, consider replacing the affected Tenda AC10 device or isolating it from critical network segments if immediate replacement is not feasible.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
