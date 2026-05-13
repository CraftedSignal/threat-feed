---
title: Uniget Command Injection Vulnerability via Malicious Metadata
slug: 2026-05-uniget-command-injection
description: Uniget is vulnerable to command injection because the `check` field is loaded directly from untrusted JSON metadata without validation, allowing an attacker to execute arbitrary shell commands on the victim's system when performing common uniget operations.
date: "2026-05-13T15:36:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - linux
vendors:
  - uniget-org
products:
  - cli
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-qqq4-5773-pmw5
  - CVE-2026-45152
rules:
  - title: Detect CVE-2026-45152 Exploitation — Uniget Command Injection via Bash Execution
    description: Detects CVE-2026-45152 exploitation — execution of bash with -c parameter and commands originating from the uniget metadata cache directory indicating a command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect CVE-2026-45152 Attempt — Uniget Metadata Cache Modification
    description: Detects attempts to create or modify Uniget metadata cache files, potentially indicating malicious activity associated with CVE-2026-45152 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Uniget is vulnerable to a command injection vulnerability (CVE-2026-45152) stemming from the unsafe execution of the `check` field within metadata files. This occurs because the `check` field, used for version checks, is executed via `/bin/bash -c` without proper sanitization or validation. An attacker can inject arbitrary shell commands by crafting malicious metadata. Common uniget operations such as `describe`, `install`, `update`, or `inspect` will trigger the vulnerability. This vulnerability affects uniget versions prior to 0.27.1, and successful exploitation leads to arbitrary code execution with the privileges of the user running uniget.

## Attack Chain

1. The attacker crafts a malicious JSON metadata file containing a payload within the `check` field.
2. The attacker places the malicious metadata file in the uniget metadata cache directory (`~/.local/var/cache/uniget/`).
3. The user executes a uniget command such as `describe`, `install`, `update`, or `inspect` targeting a tool defined in the malicious metadata.
4. Uniget loads the metadata for the specified tool using `json.Unmarshal()`.
5. The `tool.Check` field is populated with the attacker-controlled command from the JSON metadata.
6. Uniget executes the command defined in the `tool.Check` field using `/bin/bash -c`.
7. The shell interprets any shell metacharacters present in the command, resulting in command injection.
8. The attacker's injected commands are executed with the privileges of the user running uniget, potentially leading to complete system compromise.

## Impact

This command injection vulnerability allows an attacker to execute arbitrary code on a vulnerable system. This can lead to the exfiltration of sensitive data, installation of malware, or modification of system configurations. Compromised systems could be leveraged for further attacks within a network. This issue primarily affects users who import or process attacker-controlled metadata, potentially including CI/CD environments using uniget automation. Successful exploitation grants the attacker the same privileges as the user running uniget, potentially leading to complete system compromise.

## Recommendation

*   Upgrade to uniget version 0.27.1 or later to patch CVE-2026-45152.
*   Deploy the Sigma rules in this brief to your SIEM to detect exploitation attempts.
*   If upgrading is not immediately feasible, avoid using uniget with untrusted metadata sources.
*   Monitor process creation events for `/bin/bash -c` executing commands sourced from uniget metadata locations, as detected by the Sigma rules.
