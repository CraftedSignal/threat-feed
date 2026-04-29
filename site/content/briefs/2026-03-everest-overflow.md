---
title: EVerest IsoMux Certificate Filename Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-everest-overflow
description: A stack-based buffer overflow vulnerability exists in EVerest's IsoMux certificate filename handling before version 2026.02.0, potentially allowing code execution via a crafted filename.
date: "2026-03-26T15:16:31Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - buffer overflow
  - EV charging
  - code execution
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22593
  - https://github.com/EVerest/EVerest/security/advisories/GHSA-cpqf-mcqc-783m
rules:
  - title: Detect EVerest Process Creation
    description: Detects the creation of EVerest-related processes, which could indicate exploitation attempts or legitimate activity. Tune for your environment.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation in Everest Certificate Directory
    description: Detects creation of files with a length of 100 characters in the EVerest certificate directory, which could indicate an attempt to exploit CVE-2026-22593.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - file_event
      - linux
rules_count: 2
---

EVerest is an open-source software stack for electric vehicle (EV) charging infrastructure. Prior to version 2026.02.0, the IsoMux component contains a vulnerability related to certificate filename handling. Specifically, an off-by-one error occurs when validating the length of certificate filenames. If a filename in the certificate directory equals `MAX_FILE_NAME_LENGTH` (100 characters), a stack-based buffer overflow can be triggered. A malicious actor could exploit this vulnerability by creating a crafted filename, leading to the corruption of stack state and, potentially, arbitrary code execution. The vulnerability has a CVSS v3.1 score of 8.4 (HIGH). EVerest version 2026.02.0 addresses this issue with a patch.

## Attack Chain

1. An attacker identifies a vulnerable EVerest instance running a version prior to 2026.02.0.
2. The attacker gains access to the certificate directory of the EVerest IsoMux component. The method of access is not specified in the report.
3. The attacker crafts a malicious filename with a length of 100 characters (MAX_FILE_NAME_LENGTH).
4. The attacker uploads or creates the crafted file within the certificate directory.
5. When IsoMux processes the certificate directory, the off-by-one error occurs during filename length validation.
6. The `file_names[idx]` buffer overflows, overwriting adjacent stack memory.
7. The overflow corrupts critical stack data, potentially including return addresses or other function parameters.
8. Upon function return, the corrupted return address is used, redirecting execution flow to attacker-controlled code, resulting in arbitrary code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the EVerest system. This could lead to a compromise of the EV charging infrastructure, potentially disrupting charging services, modifying charging parameters, or gaining unauthorized access to sensitive data related to EV charging operations. Since EVerest is used in EV charging stations, a successful attack could impact multiple charging stations, depending on the deployment architecture, leading to a widespread disruption. The number of affected installations is currently unknown.

## Recommendation

*   Upgrade EVerest to version 2026.02.0 or later to patch the vulnerability (CVE-2026-22593).
*   Monitor file creation events within the EVerest certificate directory for filenames with a length of 100 characters using a file_event rule.
*   Implement strict access controls to the certificate directory to prevent unauthorized file uploads or creation.
*   Deploy the provided Sigma rule to detect potential exploitation attempts by monitoring process creations related to the Everest software.
