---
title: '@evomap/evolver Path Traversal Vulnerability Leads to RCE'
slug: 2026-05-evomap-path-traversal
description: A path traversal vulnerability in `@evomap/evolver` allows a malicious A2A Hub to overwrite project files, leading to remote code execution when a user fetches a malicious skill.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - rce
  - evomap
vendors:
  - evomap
products:
  - '@evomap/evolver (<= 1.70.0-beta.4)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-cfcj-hqpf-hccf
rules:
  - title: Detect Suspicious Skill ID in evomap/evolver fetch Command
    description: Detects attempts to fetch skills with suspicious skill_id values (e.g., '..') that could indicate a path traversal attack.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Overwritten index.js with Malicious Content
    description: Detects if index.js has been overwritten by malicious content
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `@evomap/evolver` package, specifically versions 1.70.0-beta.4 and earlier, contains a path traversal vulnerability in the `evolver fetch` subcommand. This vulnerability resides within `index.js` and allows a malicious A2A Hub to overwrite project files, ultimately leading to remote code execution (RCE). The flaw stems from insufficient sanitization of the `skill_id` parameter, where a regex allow-list permits the use of `.` characters. An attacker can exploit this by uploading a malicious skill to the A2A Hub with a crafted `skill_id` of `..` and a bundled file such as `index.js` containing attacker-controlled JavaScript code. When a victim fetches the malicious skill, their `index.js` file is overwritten. The next time the victim invokes `node index.js`, even with a simple command like `--help`, the malicious code executes with the victim's privileges, giving the attacker control of the victim's environment.

## Attack Chain

1. Attacker uploads a malicious skill to the A2A Hub, setting the `skill_id` to `..`. The malicious skill also includes a `bundled_files` array containing a file named `index.js` with malicious JavaScript code.
2. The victim runs `node index.js fetch --skill=anything` to download the skill.
3. The `evolver fetch` command in `index.js` uses `path.join('.', 'skills', safeId)` to determine the output directory, where `safeId` is the attacker-controlled `skill_id` after regex sanitization. Since `safeId` is `..`, the output directory resolves to the current working directory.
4. The code proceeds to iterate over the `bundled_files` array from the Hub response and writes each file to the output directory.
5. Due to the path traversal, the attacker-supplied `index.js` file overwrites the original `index.js` file in the victim's current working directory.
6. The victim subsequently invokes `node index.js <command>`, which executes the attacker-controlled JavaScript code due to the overwritten `index.js` file.
7. The attacker achieves remote code execution with the privileges of the victim's user account.
8. The attacker can maintain persistence by using the `run --loop` daemon mode and injecting commands or establishing reverse shells.

## Impact

Successful exploitation leads to remote code execution on the victim's machine with the privileges of the `evolver` process. This allows the attacker to execute arbitrary commands, install malware, steal sensitive data, or compromise the entire system. The impact is amplified because the loop daemon (`node index.js run --loop`) is the documented long-running mode, resulting in the malicious code being executed rapidly after the next daemon iteration. This vulnerability allows an attacker to compromise every user that fetches the malicious skill with a single malicious skill upload. Furthermore, the attacker can also overwrite other files like `package.json`, potentially leading to further compromise of the victim's system.

## Recommendation

- Deploy the following Sigma rule to detect attempts to download skills with suspicious `skill_id` values from the A2A Hub.
- Apply the provided patch to `index.js` to reject `safeId` values that are not single non-traversing path segments, or reuse the same `path.relative` check used in the `--out` branch.
- Consider removing `.` from the regex allow-list used to sanitize the `skill_id` parameter.
- Implement signature verification on the Hub response payload before writing any file to disk.
- Disallow bundled-file `safeName` values that match top-level project files (`index.js`, `package.json`, `package-lock.json`, etc.) regardless of `outDir`.
