---
title: Totolink X5000R Buffer Overflow Vulnerability (CVE-2026-8137)
slug: 2026-05-totolink-x5000r-bo
description: A buffer overflow vulnerability (CVE-2026-8137) exists in the Totolink X5000R router version 9.1.0u.6369_B20230113, allowing remote attackers to execute arbitrary code via manipulation of the 'submit-url' argument in the /boafrm/formDdns file.
date: "2026-05-08T05:16:11Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - buffer overflow
  - router
  - remote code execution
vendors:
  - Totolink
products:
  - X5000R 9.1.0u.6369_B20230113
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8137
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8137
  - https://github.com/Kiciot/cve/issues/4
  - https://vuldb.com/vuln/361926
rules:
  - title: Detect CVE-2026-8137 Exploitation Attempt — Malicious submit-url Parameter
    description: Detects CVE-2026-8137 exploitation attempts by identifying abnormally long 'submit-url' parameters in requests to '/boafrm/formDdns'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-8137 Exploitation Attempt — Suspicious POST to formDdns
    description: Detects CVE-2026-8137 exploitation attempts by identifying POST requests to '/boafrm/formDdns' which is unusual for this endpoint
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

A buffer overflow vulnerability, identified as CVE-2026-8137, has been discovered in Totolink X5000R router version 9.1.0u.6369_B20230113. The vulnerability resides within the `sub_458E40` function of the `/boafrm/formDdns` file. By manipulating the `submit-url` argument, a remote attacker can trigger a buffer overflow, potentially leading to arbitrary code execution on the affected device. Public exploits are available, increasing the risk of widespread exploitation. Routers are a critical component of network infrastructure, and successful exploitation could lead to denial of service, data exfiltration, or further network compromise.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink X5000R router running firmware version 9.1.0u.6369_B20230113.
2.  The attacker crafts a malicious HTTP request targeting the `/boafrm/formDdns` endpoint.
3.  The malicious request includes a `submit-url` argument with a payload exceeding the buffer's capacity in the `sub_458E40` function.
4.  The router processes the request and attempts to write the overly long `submit-url` value into the buffer.
5.  The buffer overflow occurs, overwriting adjacent memory regions.
6.  The attacker carefully crafts the overflow payload to overwrite critical function pointers or return addresses.
7.  When the vulnerable function returns, control is redirected to the attacker's injected code.
8.  The attacker's code executes with the privileges of the web server process, potentially allowing for command execution or further exploitation.

## Impact

Successful exploitation of CVE-2026-8137 allows a remote attacker to execute arbitrary code on the affected Totolink X5000R router. This could lead to a variety of negative consequences, including denial of service, unauthorized access to network resources, data exfiltration, or the installation of malware. Given the prevalence of these routers in home and small business networks, a large number of devices could be vulnerable.

## Recommendation

*   Apply available patches or firmware updates from Totolink to remediate CVE-2026-8137.
*   Deploy the Sigma rule "Detect CVE-2026-8137 Exploitation Attempt — Malicious submit-url Parameter" to identify exploitation attempts in web server logs.
*   Monitor web server logs for requests to `/boafrm/formDdns` with abnormally long `submit-url` parameters.
*   Consider implementing rate limiting on requests to `/boafrm/formDdns` to mitigate potential denial-of-service attacks.
