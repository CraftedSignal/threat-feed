---
title: PraisonAI Arbitrary File Write via Path Traversal in Recipe Unpack
slug: 2024-01-21-praisonai-path-traversal
description: A critical path traversal vulnerability in PraisonAI's `recipe unpack` allows arbitrary file writes by unpacking a malicious bundle, leading to potential privilege escalation and persistence.
date: "2024-01-21T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - arbitrary-file-write
  - praisonai
vendors:
  - PraisonAI
products:
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40157
references:
  - https://github.com/advisories/GHSA-99g3-w8gr-x37c
rules:
  - title: Detect PraisonAI Recipe Unpack Invocation
    description: Detects invocations of `praisonai recipe unpack` which may indicate an attempt to exploit CVE-2026-40157.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation After PraisonAI Recipe Unpack
    description: Detects file creation events in unexpected locations (e.g., outside the intended recipe directory) following the invocation of `praisonai recipe unpack`, potentially indicating successful path traversal exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability exists in PraisonAI versions 2.7.2 and later, but prior to 4.5.128, specifically within the `recipe unpack` functionality. This vulnerability stems from the use of raw `tar.extract()` in `src/praisonai/praisonai/cli/features/recipe.py:1170-1172` without proper validation of archive member paths. Attackers can exploit this by crafting malicious `.praison` bundles containing `../../` entries, allowing them to write files outside the intended output directory when a user unpacks the bundle. This vulnerability allows an attacker to overwrite arbitrary files on the victim's filesystem. The impact of this vulnerability could be severe, potentially leading to privilege escalation and persistence within the compromised system.

## Attack Chain

1. An attacker crafts a malicious `.praison` bundle containing files with path traversal sequences (e.g., `../../.bashrc`).
2. The attacker distributes this malicious bundle to a victim, potentially via a shared recipe repository or direct transfer.
3. The victim executes the `praisonai recipe unpack malicious.praison -o ./recipes` command.
4. The `cmd_unpack` function in `cli/features/recipe.py` processes the bundle.
5. The code iterates through each member in the tar archive without validating the member name.
6. Because `tar.extract()` is used without path sanitization, path traversal sequences like `../../` are interpreted, allowing files to be written to arbitrary locations.
7. A file, such as `.bashrc`, is written to a location outside the intended `recipes` directory.
8. The attacker achieves arbitrary file write, potentially leading to privilege escalation or persistence.

## Impact

The vulnerability in PraisonAI's `recipe unpack` functionality allows attackers to overwrite arbitrary files on the victim's system. If the attacker successfully overwrites shell configuration files such as `.bashrc` or `.zshrc`, they can achieve persistence by executing malicious code every time a new shell is opened. The attacker controls both the path and content of the files written, making it possible to inject arbitrary commands, modify SSH authorized keys, or manipulate cron entries. This can lead to full system compromise, depending on filesystem permissions and the overwritten files.

## Recommendation

*   Deploy the Sigma rule to detect command lines invoking `praisonai recipe unpack` with `.praison` files from untrusted sources to your SIEM and tune for your environment.
*   Monitor file creation events in unexpected locations after using `praisonai recipe unpack` using the "Detect Suspicious File Creation After PraisonAI Recipe Unpack" Sigma rule. Enable Sysmon file creation logging to activate the rule.
*   Upgrade PraisonAI to a version >= 4.5.128 to remediate CVE-2026-40157, which patches the vulnerable code in `src/praisonai/praisonai/cli/features/recipe.py:1170-1172`.
