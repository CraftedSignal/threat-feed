---
title: 'CVE-2026-44604: RPM rpmuncompress Command Injection Vulnerability'
slug: 2026-05-rpm-command-injection
description: A command injection vulnerability (CVE-2026-44604) exists in the `rpmuncompress` utility of RPM; when extracting specially crafted ZIP, 7z, or GEM archives, an attacker can inject shell commands via a malicious top-level folder name, leading to arbitrary code execution as the user running the extraction.
date: "2026-05-28T08:18:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - rpm
  - CVE-2026-44604
  - archive-extraction
  - linux
vendors:
  - Red Hat
products:
  - RPM
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-44604
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44604
  - https://access.redhat.com/security/cve/CVE-2026-44604
  - https://bugzilla.redhat.com/show_bug.cgi?id=2460967
rules:
  - title: Detects CVE-2026-44604 Exploitation — Archive Extraction with Shell Metacharacters in Filename
    description: Detects CVE-2026-44604 exploitation attempt — archive extraction with suspicious shell metacharacters in the filename.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.002
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detects CVE-2026-44604 Exploitation — Suspicious Process Launched After Archive Extraction
    description: Detects CVE-2026-44604 exploitation attempt — monitoring for suspicious child processes spawned after archive extractions potentially indicating command injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.002
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A command injection vulnerability, CVE-2026-44604, affects the `rpmuncompress` utility within RPM. This flaw occurs during the extraction of specific archive formats, namely ZIP, 7z, and GEM. The utility unsafely incorporates the archive's top-level folder name into a shell command without proper sanitization. By crafting a malicious archive with shell metacharacters embedded in the folder name, an attacker can inject arbitrary commands. The vulnerability can be exploited by any user able to trigger the RPM extraction process and results in command execution with the privileges of the user running the `rpmuncompress` command. This is a critical security concern as it allows for privilege escalation and system compromise.

## Attack Chain

1. An attacker crafts a malicious ZIP, 7z, or GEM archive. The archive's top-level folder name contains shell metacharacters (e.g., `;`, `|`, `&`).
2. A user is tricked into using the `rpmuncompress` utility or a similar tool that leverages it to extract the malicious archive to a specified destination directory.
3. `rpmuncompress` processes the archive and extracts the top-level folder name.
4. Due to insufficient sanitization, the crafted folder name containing shell metacharacters is incorporated into a shell command.
5. The shell command is executed by the system, interpreting the metacharacters as command separators or modifiers.
6. The injected commands execute arbitrary code within the context of the user running `rpmuncompress`.
7. The attacker gains control of the system or performs unauthorized actions.
8. The attacker achieves their objective, such as data exfiltration, installing malware, or creating new privileged accounts.

## Impact

Successful exploitation of CVE-2026-44604 allows an attacker to execute arbitrary commands on the affected system with the privileges of the user running the `rpmuncompress` utility. This can lead to complete system compromise, data theft, or denial of service. The CVSS v3.1 base score is 7.0, indicating a high severity. Given the widespread use of RPM in Linux distributions, this vulnerability poses a significant risk to a large number of systems.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect command injection attempts using shell metacharacters within archive names.
*   Where feasible, avoid using `rpmuncompress` on untrusted archives. If archive extraction is necessary, isolate the process in a sandboxed environment to limit the impact of potential command injection.
*   Apply patches or updates provided by Red Hat that address CVE-2026-44604.
*   Monitor process creation events for unusual commands being executed by `rpmuncompress` or related processes, as identified by the Sigma rules.
