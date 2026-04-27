---
title: Evolver Path Traversal Vulnerability in `fetch` Command
slug: 2024-08-evolver-path-traversal
description: A path traversal vulnerability exists in the `fetch` command of `@evomap/evolver` due to insufficient validation of the `--out` flag, allowing attackers to write files to arbitrary locations on the filesystem, potentially leading to overwriting critical system files and privilege escalation.
date: "2024-08-10T12:00:00Z"
severities:
  - high
tags:
  - path-traversal
  - arbitrary-file-write
  - privilege-escalation
  - evolver
vendors:
  - '@evomap'
products:
  - '@evomap/evolver'
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-r466-rxw4-3j9j
rules:
  - title: Detect Evolver Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability in `@evomap/evolver` by monitoring command-line arguments for path traversal sequences passed to node.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Evolver Linux Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability in `@evomap/evolver` on Linux by monitoring command-line arguments for path traversal sequences passed to node.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `@evomap/evolver` package contains a path traversal vulnerability in its `fetch` command, specifically affecting versions prior to 1.69.3. This flaw arises from the insufficient validation of user-supplied paths provided via the `--out` flag. By manipulating this flag, attackers can bypass intended directory restrictions and write files to arbitrary locations on the filesystem. This can lead to critical system file modification, potentially leading to privilege escalation and persistent…
