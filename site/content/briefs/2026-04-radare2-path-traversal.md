---
title: Radare2 Path Traversal Vulnerability in Project Deletion
slug: 2026-04-radare2-path-traversal
description: Radare2 versions prior to 6.1.4 are vulnerable to a path traversal in project deletion, allowing local attackers to recursively delete arbitrary directories by escaping the 'dir.projects' root, leading to integrity and availability loss.
date: "2026-04-23T21:16:06Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - radare2
  - local-privilege-escalation
vendors:
  - radare
products:
  - radare2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-6940
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6940
rules:
  - title: Detect Radare2 Project Deletion with Absolute Path
    description: Detects radare2 process execution attempting to delete projects using absolute paths, indicating potential path traversal exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Radare2 Process Executing with Suspicious Arguments
    description: Detects radare2 process executing potentially malicious commands indicative of exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Radare2, a reverse engineering framework, is susceptible to a path traversal vulnerability (CVE-2026-6940) affecting versions prior to 6.1.4. This flaw allows a local attacker to delete arbitrary directories outside of the intended project storage location. By crafting project marker files with absolute paths that escape the configured `dir.projects` root directory, an attacker can trick the radare2 process into recursively deleting directories they should not have access to. This vulnerability poses a significant risk to system integrity and availability, as attackers can potentially delete critical system files or data. This vulnerability was published on 2026-04-23 and could be exploited immediately.

## Attack Chain

1. Attacker gains local access to a system with radare2 installed.
2. Attacker identifies the location where radare2 stores project files (configured by `dir.projects`).
3. Attacker crafts a malicious radare2 project file containing an absolute path pointing outside the designated project directory. This path includes traversal sequences (e.g., `../`) to escape the `dir.projects` root.
4. The attacker places the malicious project marker file in a location where radare2 will discover it (e.g. a default projects directory).
5. Attacker uses radare2's project deletion functionality, specifying the malicious project for deletion.
6. Radare2, without proper validation of the project file path, recursively deletes the directory specified in the crafted path.
7. This deletion occurs with the permissions of the radare2 process, potentially allowing the attacker to delete files and directories they would normally not have access to.
8. The attacker achieves arbitrary directory deletion, leading to loss of system integrity and availability.

## Impact

Successful exploitation of this vulnerability allows a local attacker to recursively delete arbitrary directories on the affected system. This can lead to significant data loss, system instability, and denial of service. The CVSS v3.1 base score for this vulnerability is 7.1, indicating a high level of severity. While no specific victim numbers or sector targeting have been disclosed, the potential impact on any system running a vulnerable version of radare2 is substantial.

## Recommendation

*   Upgrade radare2 to version 6.1.4 or later to patch CVE-2026-6940.
*   Implement the process creation rule below to detect suspicious radare2 executions that could indicate exploitation attempts.
*   Consider limiting local user access to systems running radare2 to reduce the attack surface.
