---
title: Linux Kernel 'Copy Fail' Vulnerability Enables Root Access
slug: 2026-05-copy-fail
description: A 9-year-old Linux kernel vulnerability, dubbed 'Copy Fail' (CVE-2026-31431), allows attackers to gain root access via a memory flaw in the algif_aead module by overwriting data in the page cache.
date: "2026-04-30T07:26:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
actors:
  - Theori Xint Code Research Team
tags:
  - vulnerability
  - privilege escalation
  - linux
vendors:
  - Linux
  - Ubuntu
  - Amazon
  - Red Hat
  - SUSE
products:
  - Linux Kernel
  - Ubuntu 24.04 LTS
  - Amazon Linux 2023
  - Red Hat Enterprise Linux 10.1
  - SUSE 16
affected_os:
  - Ubuntu 24.04 LTS
  - Amazon Linux 2023
  - Red Hat Enterprise Linux 10.1
  - SUSE 16
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.008
    technique_name: 'Command and Scripting Interpreter: Python'
cves:
  - id: CVE-2026-31431
    cvss: 7.8
    epss: 8e-05
references:
  - https://hackread.com/linux-kernel-vulnerability-copy-fail-full-root-access/
iocs:
  - type: url
    value: https://copy.fail/public/demo.mp4
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious Python Cryptographic Module Usage
    description: Detects execution of Python scripts that import and use cryptographic modules, which could indicate exploitation attempts related to CVE-2026-31431.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.008
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of /usr/bin/su Memory via Page Cache
    description: Detects suspicious attempts to modify the memory of the /usr/bin/su binary, indicating a potential exploitation of CVE-2026-31431.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The Theori Xint Code Research Team discovered a critical vulnerability, CVE-2026-31431, in the Linux kernel's cryptographic subsystem, specifically the algif_aead module. Dubbed "Copy Fail," this vulnerability has existed since 2017 and allows a regular user to gain full root access on a vulnerable system. The vulnerability stems from a flaw in the authencesn tool, where it incorrectly writes four bytes of information into the page cache due to a speed-up change introduced in 2017. This memory corruption can be exploited to modify privileged files, such as /usr/bin/su, leading to unauthorized privilege escalation. The researchers demonstrated the exploit using a 732-byte Python script, highlighting its simplicity and reliability across different Linux distributions.

## Attack Chain

1. A normal user executes a malicious Python script (732 bytes).
2. The script leverages the CVE-2026-31431 vulnerability in the algif_aead module.
3. The vulnerability causes a four-byte write to an incorrect location in the page cache.
4. This write corrupts the memory of a privileged file, such as /usr/bin/su.
5. When /usr/bin/su is executed, it runs with the corrupted memory.
6. The attacker gains an elevated (root) shell due to the modified /usr/bin/su binary.
7. The attacker now has complete control over the system.

## Impact

Successful exploitation of the "Copy Fail" vulnerability (CVE-2026-31431) grants an attacker full root access to the compromised system. The vulnerability is present across multiple Linux distributions, including Ubuntu 24.04 LTS, Amazon Linux 2023, Red Hat Enterprise Linux 10.1, and SUSE 16, potentially affecting a large number of systems. The attack leaves minimal forensic traces, as the modifications occur in memory rather than on disk. This makes it difficult for traditional file integrity monitoring tools to detect the compromise.

## Recommendation

*   Apply the latest kernel patch, specifically commit a664bf3d603d, to remediate CVE-2026-31431.
*   If patching is not immediately feasible, disable the algif_aead module to mitigate the vulnerability, as suggested in the overview.
*   Monitor for execution of unusual or suspicious python scripts, especially those interacting with cryptographic modules, using process creation logging and the "Detect Suspicious Python Cryptographic Module Usage" Sigma rule.
