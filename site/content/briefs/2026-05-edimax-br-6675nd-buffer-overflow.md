---
title: Edimax BR-6675nD Remote Buffer Overflow Vulnerability (CVE-2026-9381)
slug: 2026-05-edimax-br-6675nd-buffer-overflow
description: A remote buffer overflow vulnerability (CVE-2026-9381) exists in the `formPPPoESetup` function of the Edimax BR-6675nD 1.12 router's web management interface, allowing unauthenticated attackers to potentially execute arbitrary code by manipulating the `pppUserName` argument in a POST request.
date: "2026-05-26T13:48:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer overflow
  - remote code execution
  - cve
vendors:
  - Edimax
products:
  - BR-6675nD 1.12
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-9381
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9381
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR-6675nD-formPPPoESetup-34b53a41781f803faf50d4caf940d2dc?source=copy_link
  - https://vuldb.com/submit/811559
  - https://vuldb.com/vuln/365344
  - https://vuldb.com/vuln/365344/cti
rules:
  - title: Detect CVE-2026-9381 Exploitation Attempt via Long pppUserName
    description: Detects CVE-2026-9381 exploitation — Monitors web server logs for POST requests to /goform/formPPPoESetup with unusually long pppUserName values, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9381 Exploitation Success via Shell Spawn
    description: Detects CVE-2026-9381 exploitation — Monitors process creation for shell processes spawned from a process associated with web requests, potentially indicating command execution following a buffer overflow.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-9381, has been discovered in Edimax BR-6675nD version 1.12. The vulnerability resides within the `formPPPoESetup` function located in the `/goform/formPPPoESetup` file, which handles POST requests to the device's web interface. An attacker can trigger a buffer overflow by manipulating the `pppUserName` argument passed to this function. The vulnerability is remotely exploitable and, due to the publication of a public exploit, poses an elevated risk. The vendor, Edimax, has reportedly not responded to vulnerability disclosure attempts.

## Attack Chain

1. An attacker identifies an Edimax BR-6675nD router running firmware version 1.12.
2. The attacker crafts a malicious HTTP POST request targeting the `/goform/formPPPoESetup` endpoint.
3. The POST request includes the `pppUserName` parameter with a value exceeding the expected buffer size.
4. The router's web server processes the POST request and passes the oversized `pppUserName` value to the `formPPPoESetup` function.
5. The `formPPPoESetup` function attempts to copy the attacker-controlled `pppUserName` value into a fixed-size buffer without proper bounds checking.
6. The buffer overflow occurs, overwriting adjacent memory regions on the stack or heap.
7. The attacker leverages the overflow to overwrite critical data such as return addresses, potentially hijacking control flow.
8. Upon function return, the overwritten return address redirects execution to attacker-controlled code, achieving remote code execution.

## Impact

Successful exploitation of CVE-2026-9381 can lead to arbitrary code execution on the affected Edimax BR-6675nD router. This can allow an attacker to gain complete control of the device, potentially enabling them to intercept network traffic, modify router configurations, or use the router as a pivot point for further attacks within the network. Given the widespread use of Edimax routers in home and small business environments, a large number of devices are potentially vulnerable.

## Recommendation

*   Monitor web server logs for suspicious POST requests to `/goform/formPPPoESetup` with unusually long `pppUserName` values to detect potential exploitation attempts (see Sigma rule `Detect CVE-2026-9381 Exploitation Attempt via Long pppUserName`).
*   Implement rate limiting on POST requests to the `/goform/formPPPoESetup` endpoint to mitigate potential brute-force exploitation attempts.
*   Deploy the Sigma rule `Detect CVE-2026-9381 Exploitation Success via Shell Spawn` to identify command execution following successful exploitation.
*   Contact Edimax support and request a security patch for CVE-2026-9381 to address the underlying vulnerability.
