---
title: NVIDIA DALI Deserialization Vulnerability (CVE-2026-24156)
slug: 2026-04-nvidia-dali-deserialization
description: NVIDIA DALI contains a deserialization of untrusted data vulnerability, identified as CVE-2026-24156, which may lead to arbitrary code execution.
date: "2026-04-07T18:16:39Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-24156
  - deserialization
  - nvidia
  - dali
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-24156
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24156
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5811
  - https://www.cve.org/CVERecord?id=CVE-2026-24156
rules:
  - title: Detect DALI Process Spawning Suspicious Child Processes
    description: Detects instances where DALI spawns child processes indicative of potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect DALI Deserialization via Command Line
    description: Detects suspicious command-line arguments passed to DALI indicating potential deserialization attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-24156 describes a deserialization of untrusted data vulnerability within NVIDIA DALI. This vulnerability could allow an attacker to execute arbitrary code on a vulnerable system. According to NVIDIA's advisory, a successful exploit requires local access, a low level of privileges, and user interaction. The CVSS v3.1 score is rated as 7.3 (HIGH). The vulnerability was reported on April 7, 2026. Successful exploitation could allow an attacker to compromise the confidentiality, integrity, and availability of the system. This is a critical vulnerability for systems utilizing NVIDIA DALI, especially those processing external or untrusted data.

## Attack Chain

1. An attacker gains local access to a system running NVIDIA DALI, possibly through social engineering or physical access.
2. The attacker prepares a malicious serialized data object designed to exploit the deserialization vulnerability in DALI.
3. The attacker leverages user interaction to trigger the deserialization process within DALI, potentially through a crafted input file or command-line argument.
4. During deserialization, the malicious object executes arbitrary code due to the vulnerability.
5. The attacker gains control of the DALI process, potentially escalating privileges within the application context.
6. The attacker uses the compromised DALI process to execute commands on the host operating system.
7. The attacker compromises the system, potentially installing malware, exfiltrating sensitive data, or causing denial of service.

## Impact

Successful exploitation of CVE-2026-24156 can lead to arbitrary code execution on systems running NVIDIA DALI. This could result in complete system compromise, including data theft, system corruption, and denial of service. Given the CVSS score of 7.3, the impact is considered high, as successful exploitation can severely impact confidentiality, integrity, and availability.

## Recommendation

*   Apply the patch or upgrade to the version of NVIDIA DALI that addresses CVE-2026-24156, as described in NVIDIA's advisory.
*   Implement least privilege principles to limit the impact of potential code execution.
*   Monitor systems for suspicious process execution originating from DALI processes to detect potential exploitation attempts.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
