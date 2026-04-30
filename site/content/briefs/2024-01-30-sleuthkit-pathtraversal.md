---
title: Sleuth Kit Path Traversal Vulnerability (CVE-2026-40024)
slug: 2024-01-30-sleuthkit-pathtraversal
description: A path traversal vulnerability exists in The Sleuth Kit through 4.14.0 (tsk_recover), enabling attackers to write files to arbitrary locations via crafted filenames with path traversal sequences in a filesystem image, potentially leading to code execution.
date: "2026-04-08T22:16:22Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path traversal
  - code execution
  - privilege escalation
  - sleuth kit
  - CVE-2026-40024
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1553
    technique_name: Subvert Trust Relationships
cves:
  - id: CVE-2026-40024
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40024
rules:
  - title: Detect Sleuth Kit Path Traversal
    description: Detects attempts to write files outside the intended recovery directory using tsk_recover, indicating potential path traversal exploitation.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-40024
      - persistence
      - privilege_escalation
    techniques:
      - T1553
    data_sources:
      - process_creation
      - linux
  - title: Detect File Creation in Suspicious Paths by tsk_recover
    description: Detects file creation events in sensitive directories by the tsk_recover process. This can indicate a path traversal attack where the tool is writing files outside of its intended directory.
    platform: sigma
    severity: critical
    tactics:
      - cve-2026-40024
      - persistence
      - privilege_escalation
    techniques:
      - T1553
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Sleuth Kit, a collection of command-line tools for forensic analysis of disk images, is susceptible to a path traversal vulnerability (CVE-2026-40024) affecting versions up to 4.14.0. This vulnerability resides within the `tsk_recover` utility, which is designed to recover files from disk images. An attacker can exploit this flaw by crafting a malicious filesystem image containing filenames or directory paths with path traversal sequences (e.g., `../`). When `tsk_recover` processes this image, it can be tricked into writing files to arbitrary locations outside the intended recovery directory. Successful exploitation allows attackers to overwrite critical system files, such as shell configuration files or cron entries, ultimately leading to code execution with elevated privileges. This vulnerability poses a significant risk to systems utilizing The Sleuth Kit for forensic investigations.

## Attack Chain

1.  Attacker crafts a malicious filesystem image. This image contains filenames or directory paths embedded with path traversal sequences like `../`.
2.  The attacker, or a user under their control, invokes the `tsk_recover` utility on a vulnerable system, specifying the malicious filesystem image as input.
3.  `tsk_recover` parses the filesystem image and encounters the crafted filenames with path traversal sequences.
4.  Due to the vulnerability, `tsk_recover` incorrectly resolves the file paths, allowing the write operation to escape the intended recovery directory.
5.  The utility writes a file to an arbitrary location on the file system. This location is determined by the attacker-controlled path traversal sequences.
6.  The attacker strategically targets critical system files for overwriting, such as shell configuration files (`.bashrc`, `.bash_profile`) or cron entries (`/etc/cron.d/`).
7.  Upon the next user login or scheduled cron job execution, the attacker's malicious code embedded in the overwritten files is executed.
8.  The attacker achieves code execution, potentially gaining persistence or escalating privileges on the compromised system.

## Impact

Successful exploitation of this vulnerability allows an attacker to write arbitrary files to the target system, potentially leading to code execution. By overwriting shell configuration files or cron entries, attackers can gain persistence and escalate their privileges, effectively taking control of the system. While the specific number of victims is unknown, any system utilizing a vulnerable version of The Sleuth Kit for disk image analysis is at risk. The impact could range from data theft to complete system compromise, depending on the attacker's objectives and the level of access gained.

## Recommendation

*   Upgrade The Sleuth Kit to a version beyond 4.14.0 to patch CVE-2026-40024 and eliminate the path traversal vulnerability.
*   Monitor process execution for instances of `tsk_recover` writing files outside the intended recovery directory using the Sigma rule `Detect Sleuth Kit Path Traversal`.
*   Implement file integrity monitoring for critical system files (e.g., `.bashrc`, `.bash_profile`, `/etc/cron.d/*`) to detect unauthorized modifications resulting from exploitation of CVE-2026-40024.
