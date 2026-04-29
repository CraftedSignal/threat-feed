---
title: Tenda CX12L Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-cx12l-buffer-overflow
description: A stack-based buffer overflow vulnerability exists in the Tenda CX12L router (version 16.03.53.12) due to improper handling of the 'page' argument in the 'fromwebExcptypemanFilter' function, potentially allowing attackers with local network access to execute arbitrary code.
date: "2026-04-06T22:16:24Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - tenda
  - router
  - buffer-overflow
  - cve-2026-5684
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-5684
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5684
  - https://github.com/cve-a/lvdan/issues/2
  - https://vuldb.com/vuln/355511
rules:
  - title: Detect Tenda CX12L Web Request with Long Page Parameter
    description: Detects HTTP requests to the vulnerable Tenda CX12L endpoint with a large 'page' parameter, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda CX12L Stack Buffer Overflow Attempt
    description: Detects suspicious processes spawned after a potential webserver exploit on Tenda CX12L routers, indicative of code execution following a buffer overflow.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability has been identified in Tenda CX12L routers running firmware version 16.03.53.12. The vulnerability resides within the `fromwebExcptypemanFilter` function in the `/goform/webExcptypemanFilter` file.  An attacker with local network access can exploit this flaw by manipulating the `page` argument passed to this function, leading to arbitrary code execution on the device. The vulnerability, identified as CVE-2026-5684, has a CVSS v3.1 score of 8.0, indicating a high severity. Public exploits for this vulnerability are available, making it crucial for network administrators to address this issue promptly. Successful exploitation could allow an attacker to gain complete control of the router, potentially leading to data theft, network compromise, or denial of service.

## Attack Chain

1.  Attacker gains access to the local network where the Tenda CX12L router is located.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/webExcptypemanFilter` endpoint.
3.  The crafted request includes a `page` argument with a payload exceeding the buffer size allocated for it within the `fromwebExcptypemanFilter` function.
4.  The router processes the HTTP request and passes the overly long `page` argument to the vulnerable function.
5.  The `fromwebExcptypemanFilter` function attempts to write the contents of the `page` argument into a fixed-size buffer on the stack.
6.  Due to the excessive length of the `page` argument, the buffer overflows, overwriting adjacent memory regions on the stack.
7.  The attacker leverages the buffer overflow to overwrite the return address on the stack with the address of malicious code or a ROP chain.
8.  When the `fromwebExcptypemanFilter` function returns, control is transferred to the attacker-controlled code, allowing for arbitrary code execution.

## Impact

Successful exploitation of CVE-2026-5684 allows an attacker with local network access to gain complete control of the affected Tenda CX12L router. This can lead to a variety of malicious activities, including unauthorized access to network traffic, modification of router settings, deployment of malicious firmware, and use of the compromised router as a botnet node. Given the availability of public exploits, organizations using this router model are at significant risk. The number of potential victims is dependent on the number of unpatched Tenda CX12L devices deployed.

## Recommendation

*   Monitor webserver logs for HTTP requests targeting the `/goform/webExcptypemanFilter` endpoint with abnormally long `page` parameters to detect potential exploitation attempts. (Log Source: webserver, Rule: "Detect Tenda CX12L Web Request with Long Page Parameter")
*   Deploy the Sigma rule "Detect Tenda CX12L Stack Buffer Overflow Attempt" to identify suspicious process creations following a potential exploit.
*   Review and restrict local network access to the Tenda CX12L router to reduce the attack surface, as the exploit requires local network access.
*   Contact Tenda for a security patch or firmware update to address CVE-2026-5684.
