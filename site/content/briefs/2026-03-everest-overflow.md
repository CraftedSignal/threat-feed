---
title: EVerest IsoMux Certificate Filename Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-everest-overflow
description: A stack-based buffer overflow vulnerability exists in EVerest's IsoMux certificate filename handling before version 2026.02.0, potentially allowing code execution via a crafted filename.
date: "2026-03-26T15:16:31Z"
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

EVerest is an open-source software stack for electric vehicle (EV) charging infrastructure. Prior to version 2026.02.0, the IsoMux component contains a vulnerability related to certificate filename handling. Specifically, an off-by-one error occurs when validating the length of certificate filenames. If a filename in the certificate directory equals `MAX_FILE_NAME_LENGTH` (100 characters), a stack-based buffer overflow can be triggered. A malicious actor could exploit this vulnerability by…
