---
title: OFFIS DCMTK Command Injection Vulnerability (CVE-2026-5663)
slug: 2026-04-dcmtk-command-injection
description: A remote command injection vulnerability exists in OFFIS DCMTK version 3.7.0 and earlier due to insufficient input sanitization in the `storescp` application, potentially allowing unauthenticated attackers to execute arbitrary OS commands.
date: "2026-04-06T15:17:16Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - command-injection
  - dcmtk
  - cve-2026-5663
  - storescp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5663
    cvss: 7.3
    epss: 0.01761
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5663
  - https://github.com/DCMTK/dcmtk/commit/edbb085e45788dccaf0e64d71534cfca925784b8
  - https://vuldb.com/vuln/355486
rules:
  - title: Suspicious Processes Spawned by storescp
    description: Detects suspicious processes spawned by the storescp application, indicative of command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: DCMTK storescp Network Connection to Uncommon Ports
    description: Detects network connections from storescp to uncommon ports, possibly indicating command and control activity after exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-5663, affects OFFIS DCMTK (Dicom ToolKit) versions up to 3.7.0. The vulnerability is located within the `storescp` application, specifically in the `executeOnReception` and `executeOnEndOfStudy` functions of the `dcmnet/apps/storescp.cc` file. An attacker can exploit this flaw by manipulating input parameters processed by these functions, leading to arbitrary OS command execution on the server. Remote exploitation is possible, making this a critical issue for systems utilizing vulnerable DCMTK versions. Applying the patch edbb085e45788dccaf0e64d71534cfca925784b8, available on the DCMTK GitHub repository, is the recommended course of action.

## Attack Chain

1. An attacker identifies a vulnerable OFFIS DCMTK instance running `storescp` exposed on the network.
2. The attacker crafts a malicious DICOM request containing specially crafted parameters designed to exploit the command injection vulnerability in the `executeOnReception` or `executeOnEndOfStudy` functions.
3. The `storescp` application receives the malicious DICOM request.
4. The vulnerable `executeOnReception` or `executeOnEndOfStudy` functions process the attacker-controlled parameters without proper sanitization.
5. The application attempts to execute a system command using the unsanitized input, injecting attacker-supplied code.
6. The injected code executes arbitrary commands on the underlying operating system with the privileges of the `storescp` process.
7. The attacker gains the ability to read sensitive files, modify system configurations, or execute malicious binaries.
8. The attacker establishes persistence on the system or pivots to other internal resources.

## Impact

Successful exploitation of CVE-2026-5663 can lead to complete compromise of the affected system. This allows an attacker to execute arbitrary commands, potentially leading to data theft, denial of service, or further propagation within the network. The healthcare sector, which relies heavily on DICOM for medical imaging, is particularly at risk. Unpatched DCMTK instances expose sensitive patient data and critical infrastructure to potential attacks.

## Recommendation

*   Apply the patch `edbb085e45788dccaf0e64d71534cfca925784b8` from the DCMTK GitHub repository to remediate CVE-2026-5663 immediately.
*   Monitor network traffic for suspicious activity originating from or directed to DCMTK servers, specifically looking for unusual command execution patterns (see Sigma rule below).
*   Implement input validation and sanitization for all user-supplied data processed by DCMTK applications to prevent command injection vulnerabilities in the future.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
