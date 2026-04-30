---
title: Evolver Path Traversal Vulnerability in `fetch` Command
slug: 2024-08-evolver-path-traversal
description: A path traversal vulnerability exists in the `fetch` command of `@evomap/evolver` due to insufficient validation of the `--out` flag, allowing attackers to write files to arbitrary locations on the filesystem, potentially leading to overwriting critical system files and privilege escalation.
date: "2024-08-10T12:00:00Z"
type: advisory
types:
  - advisory
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

The `@evomap/evolver` package contains a path traversal vulnerability in its `fetch` command, specifically affecting versions prior to 1.69.3. This flaw arises from the insufficient validation of user-supplied paths provided via the `--out` flag. By manipulating this flag, attackers can bypass intended directory restrictions and write files to arbitrary locations on the filesystem. This can lead to critical system file modification, potentially leading to privilege escalation and persistent backdoor installation. The vulnerability exists in the `index.js` file, where the application processes the `--out` flag without proper sanitization before writing files to the specified directory. This is particularly concerning in automated environments like CI/CD pipelines where user input might be indirectly injected into the `fetch` command.

## Attack Chain

1.  The attacker gains control over the input to the `fetch` command, including the `--out` flag.
2.  The attacker crafts a malicious `--out` parameter containing path traversal sequences (e.g., `../../../`).
3.  The `fetch` command in `index.js` processes the `--out` flag and extracts the user-provided path without validation.
4.  The application attempts to create the directory specified by the manipulated `--out` flag using `fs.mkdirSync` with the `recursive` option.
5.  The application writes files (e.g., downloaded skill files) to the directory specified in the `--out` parameter using `fs.writeFileSync`, effectively writing to an arbitrary location.
6.  If the attacker has sufficient privileges, they can overwrite critical system files or create new files in sensitive directories like `/etc/cron.d`.
7.  The attacker leverages the modified files to achieve persistence (e.g., by creating a cron job).
8.  The attacker executes malicious code, gaining unauthorized access or escalating privileges.

## Impact

Successful exploitation of this vulnerability allows an attacker to write files to arbitrary locations on the filesystem. This can lead to several critical consequences, including overwriting system configuration files, installing persistent backdoors via cron jobs, modifying SSH authorized_keys for unauthorized access, and potentially achieving privilege escalation if the affected process runs with elevated privileges. The impact is particularly severe in automated environments where this tool is used to deploy code, as it opens the door for supply chain attacks. This issue affects users of `@evomap/evolver` prior to version 1.69.3.

## Recommendation

*   Upgrade the `@evomap/evolver` package to version 1.69.3 or later to remediate the path traversal vulnerability.
*   Deploy the Sigma rule `Detect Evolver Path Traversal Attempt` to identify exploitation attempts based on command-line arguments.
*   Monitor process creation events for command-line arguments containing path traversal sequences like `../` when executing `node` or `nodejs` related to evolver.
