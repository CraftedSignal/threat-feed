---
title: Tenda F456 Router Buffer Overflow Vulnerability (CVE-2026-9389)
slug: 2026-05-tenda-buffer-overflow
description: Tenda F456 version 1.0.0.5 is vulnerable to a buffer overflow in the frmL7ImForm function of the /goform/L7Im file, allowing a remote attacker to execute arbitrary code by manipulating the 'page' argument.
date: "2026-05-26T13:49:07Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - buffer-overflow
  - router
  - cve
  - tenda
vendors:
  - Tenda
products:
  - F456 1.0.0.5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-9389
    cvss: 8.8
    epss: 0.00046
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9389
  - https://github.com/Litengzheng/vuldb_new/blob/main/F456/vul_2/README.md
  - https://vuldb.com/submit/813444
  - https://vuldb.com/vuln/365352
  - https://vuldb.com/vuln/365352/cti
  - https://www.tenda.com.cn/
rules:
  - title: Detects CVE-2026-9389 Exploitation Attempt - Tenda F456 Buffer Overflow
    description: Detects CVE-2026-9389 exploitation attempt — Monitor for abnormally long page parameters in POST requests to /goform/L7Im, indicative of a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-9389 Exploitation Attempt - Tenda F456 HTTP POST with Potential Shell Command
    description: Detects CVE-2026-9389 exploitation attempt — Detects potential shell command injection attempts within the 'page' parameter of HTTP POST requests to /goform/L7Im.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-9389, exists in Tenda F456 version 1.0.0.5. This flaw resides within the `frmL7ImForm` function of the `/goform/L7Im` file. By carefully crafting the `page` argument, a remote attacker can trigger a buffer overflow, potentially leading to arbitrary code execution on the affected device. The vulnerability can be exploited remotely and has a publicly available exploit, increasing the risk of exploitation in the wild. This vulnerability poses a significant threat to users of the Tenda F456 router, potentially allowing attackers to gain unauthorized access to the network and connected devices.

## Attack Chain

1.  Attacker identifies a Tenda F456 router running firmware version 1.0.0.5.
2.  Attacker crafts a malicious HTTP request targeting the `/goform/L7Im` endpoint.
3.  The HTTP request includes a `page` argument with a payload designed to overflow the buffer in the `frmL7ImForm` function.
4.  The router processes the malicious HTTP request, passing the `page` argument to the vulnerable function.
5.  The `frmL7ImForm` function copies the attacker-controlled `page` argument into a fixed-size buffer without proper bounds checking.
6.  The oversized `page` argument overflows the buffer, overwriting adjacent memory regions, including return addresses or function pointers.
7.  The overwritten return address is used when the `frmL7ImForm` function returns, redirecting execution to attacker-controlled code.
8.  The attacker gains arbitrary code execution on the router, potentially leading to full system compromise and control over network traffic.

## Impact

Successful exploitation of this vulnerability could allow an attacker to gain complete control over the Tenda F456 router. This could lead to a variety of malicious activities, including eavesdropping on network traffic, injecting malicious code into web pages, or using the router as a botnet node. Given the widespread use of Tenda routers in home and small office environments, a large number of devices could be at risk.

## Recommendation

*   Monitor web server logs for suspicious POST requests to `/goform/L7Im` with abnormally long `page` parameters to detect potential exploitation attempts, using the `webserver` category in the Sigma rule below.
*   Apply firmware updates from Tenda as soon as they become available to patch CVE-2026-9389.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect exploitation attempts in your environment.
