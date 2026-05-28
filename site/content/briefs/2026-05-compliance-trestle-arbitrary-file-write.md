---
title: compliance-trestle Arbitrary File Write via Path Traversal
slug: 2026-05-compliance-trestle-arbitrary-file-write
description: The compliance-trestle application is vulnerable to arbitrary file write via path traversal; the `-o/--output` argument in `trestle author jinja` allows writing files outside the intended workspace due to improper validation of path traversal characters, leading to potential CI/CD compromise or local code execution by overwriting sensitive files such as `.github/workflows/*.yml` or `.git/hooks/*`.
date: "2026-05-28T17:56:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary file write
  - path traversal
  - compliance-trestle
  - github actions
  - CI/CD compromise
vendors:
  - GitHub
products:
  - compliance-trestle
  - github.com
affected_os:
  - Windows 11
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-4q5v-7g7x-j79w
  - CVE-2026-46345
rules:
  - title: Detect CVE-2026-46345 Exploitation Attempt - Compliance Trestle Path Traversal
    description: Detects CVE-2026-46345 exploitation attempt by monitoring process execution with suspicious output paths in compliance-trestle.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-46345 - Compliance Trestle Absolute Path File Write
    description: Detects CVE-2026-46345 - Detects compliance-trestle writing to an absolute file path, bypassing intended workspace.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The compliance-trestle application, specifically the `trestle author jinja` command, is susceptible to an arbitrary file write vulnerability due to insufficient validation of the output path. By manipulating the `-o/--output` argument, an attacker can write files to locations outside the intended workspace directory. This is because the application fails to properly sanitize path traversal characters such as `../` and `..\`, as well as absolute paths. This vulnerability was reported on May 28, 2026. Successful exploitation can lead to overwriting critical files, potentially compromising CI/CD pipelines or enabling local code execution. This poses a significant risk to systems using compliance-trestle, particularly in automated environments where file integrity is crucial. The vulnerability affects compliance-trestle versions prior to 4.0.3 and versions up to 3.12.1.

## Attack Chain

1. The attacker gains local access to a system with compliance-trestle installed.
2. The attacker crafts a malicious template file (e.g., `template.j2`) containing arbitrary content.
3. The attacker executes the `trestle author jinja` command, specifying the malicious template file using the `-i` parameter.
4. The attacker uses the `-o` parameter to specify an output path containing path traversal sequences (e.g., `subdir\..\..\..\..\..\poc.txt`) or an absolute path.
5. Due to insufficient validation, the application writes the content of the template file to the attacker-specified location outside the intended workspace.
6. The attacker overwrites a sensitive file, such as `.github/workflows/*.yml` or `.git/hooks/*`.
7. If a `.github/workflows/*.yml` file is overwritten, the next CI/CD run executes attacker-controlled code.
8. If a `.git/hooks/*` file is overwritten, a subsequent `git` command executes attacker-controlled code.

## Impact

Successful exploitation of this vulnerability allows an attacker to write arbitrary files outside the intended workspace directory, potentially overwriting sensitive files writable by the user running the `trestle` command. This can lead to various impacts, including CI/CD compromise by overwriting `.github/workflows/*.yml` files, resulting in the execution of attacker-controlled GitHub Actions workflows. Overwriting `.git/hooks/*` files can lead to local code execution when git commands are run. Additionally, user configuration files such as `.bashrc` can be modified, and repository files and generated compliance artifacts can be tampered with. In CI/CD environments, this can result in the execution of attacker-controlled commands on build runners, leading to potential data breaches or system compromise.

## Recommendation

*   Apply the patch or upgrade to compliance-trestle version 4.0.3 or later to address CVE-2026-46345.
*   Deploy the Sigma rules provided in this brief to detect exploitation attempts.
*   Implement strict input validation on the `-o/--output` argument within `trestle author jinja` to prevent path traversal (reference vulnerability description).
*   Monitor file system events for suspicious file writes outside the intended workspace directory using process creation logs.
