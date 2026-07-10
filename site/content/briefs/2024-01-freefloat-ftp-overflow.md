---
title: FreeFloat FTP Server 1.0 STOR Command Buffer Overflow
slug: 2024-01-freefloat-ftp-overflow
description: FreeFloat FTP Server 1.0 is vulnerable to a buffer overflow in the STOR command handler, enabling remote attackers to execute arbitrary code by sending a crafted STOR request with an oversized payload.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2019-25614
  - buffer-overflow
  - ftp
  - stor
  - code-execution
  - windows
vendors:
  - FreeFloat
products:
  - FreeFloat FTP Server
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25614
rules:
  - title: Detect Suspicious FTP STOR Command Payload
    description: Detects potentially malicious FTP STOR commands with abnormally large payloads, indicative of buffer overflow attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious FTP Anonymous Login Followed by Large STOR
    description: Detects anonymous FTP login followed by a large STOR command, which may indicate a buffer overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

FreeFloat FTP Server version 1.0 is susceptible to a buffer overflow vulnerability (CVE-2019-25614) within the handling of the STOR command. This flaw allows unauthenticated remote attackers to execute arbitrary code on the affected system. The attack involves sending a specially crafted STOR request to the FTP server, exploiting a lack of proper bounds checking when processing the incoming data. Successful exploitation grants the attacker complete control over the compromised server, potentially leading to data exfiltration, system disruption, or further lateral movement within the network. This vulnerability poses a significant risk to organizations utilizing the outdated and unsupported FreeFloat FTP Server 1.0 software.

## Attack Chain

1. The attacker connects to the FTP server using anonymous credentials.
2. The attacker sends a "STOR" command to initiate a file upload.
3. The attacker sends a crafted payload with 247 bytes of padding.
4. The attacker includes a return address within the crafted payload to redirect execution flow.
5. The attacker injects shellcode into the payload to perform malicious actions.
6. The FTP server's STOR command handler processes the oversized payload without proper bounds checking.
7. The buffer overflow overwrites the return address on the stack.
8. Upon function return, execution jumps to the attacker-controlled shellcode, granting arbitrary code execution.

## Impact

Successful exploitation of this buffer overflow vulnerability allows remote attackers to execute arbitrary code on the FreeFloat FTP server. This can lead to complete system compromise, potentially resulting in data theft, denial-of-service, or further malicious activity within the network. Given the nature of FTP servers as data repositories, the impact can be significant for organizations using affected versions. The CVSS v3.1 score of 9.8 reflects the critical severity of this vulnerability.

## Recommendation

*   Upgrade or discontinue use of FreeFloat FTP Server 1.0 immediately, as it is no longer supported and contains known vulnerabilities.
*   Deploy the Sigma rule "Detect Suspicious FTP STOR Command Payload" to identify potentially malicious STOR requests (see the `rules` section).
*   Monitor network traffic for unusually large payloads associated with FTP STOR commands.
