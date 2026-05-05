---
title: gitoxide Arbitrary Command Execution via .gitmodules Bypass
slug: 2024-01-09-gitoxide-rce
description: A vulnerability in gitoxide's `gix_submodule::File::update()` allows arbitrary command execution via a crafted `.gitmodules` file by incorrectly validating the source of the `update` command, enabling an attacker to inject malicious commands after a submodule has been initialized.
date: "2024-01-09T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-vulnerability
  - remote-code-execution
  - gitoxide
vendors:
  - GitoxideLabs
products:
  - gix
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2019-19604
    cvss: 7.8
    epss: 0.01339
references:
  - https://github.com/advisories/GHSA-f26g-jm89-4g65
  - https://nvd.nist.gov/vuln/detail/cve-2019-19604
rules:
  - title: Detect Suspicious Submodule Update Command Execution
    description: Detects execution of commands specified in submodule update configurations, which could indicate exploitation of the gitoxide vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Git Configuration Modification with Suspicious Submodule Update
    description: Detects modifications to git configuration files that include suspicious submodule update commands.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in gitoxide's `gix_submodule::File::update()` function, specifically in versions 0.31.0 to 0.82.0, that allows for arbitrary command execution. The vulnerability arises from an insufficient check on the origin of the `update` command specified in a `.gitmodules` file.  An attacker can exploit this by pushing a new commit with a malicious `update` command in `.gitmodules` after the victim initializes the submodule.  This bypasses the intended security guard, leading to potential remote command execution in downstream code that relies on `Submodule::update()` and trusts the safety of `Update::Command(_)`. This issue is similar to CVE-2019-19604, highlighting the risk of unchecked commands in submodule configurations.

## Attack Chain

1. An attacker creates a repository with a benign `.gitmodules` file, containing no `update` key.
2. A victim clones the attacker's repository and runs `git submodule init`, which populates the `.git/config` file with submodule information (URL, active status), but not the `update` key.
3. The attacker pushes a new commit to the repository, adding a malicious `update = !<command>` line to the `.gitmodules` file (e.g., `update = !touch /tmp/pwned`).
4. The victim runs `git pull` to update their local repository, incorporating the attacker's modified `.gitmodules` file. The `.git/config` file remains unchanged.
5. A gitoxide-based application calls `Submodule::update()` to determine the submodule update strategy.
6. The vulnerable `gix_submodule::File::update` function is called, which incorrectly validates the source of the `update` command.
7. The function checks that a submodule section with the same name exists in a non-.gitmodules source, but does not verify if the update value comes from that section, bypassing the intended security guard.
8. The attacker-controlled shell command from the `.gitmodules` file is executed, leading to arbitrary command execution.

## Impact

The vulnerability allows an attacker to execute arbitrary commands on a system running gitoxide-based applications that utilize submodules. This could lead to complete system compromise, data exfiltration, or denial of service. Any tool, IDE plugin, or CI integration building submodule-update functionality on top of `gix` within the affected version range inherits this vulnerability.  Successful exploitation depends on the vulnerable application's trust in the output of `Submodule::update()` which determines the update strategy.

## Recommendation

*   Upgrade to `gix` version 0.83.0 or later to patch the vulnerability (https://github.com/advisories/GHSA-f26g-jm89-4g65).
*   Implement additional validation and sanitization of submodule configurations, especially when handling `Update::Command(_)` from `Submodule::update()`, to prevent unintended command execution.
*   Deploy the Sigma rule below to detect potential exploitation attempts by monitoring for the execution of unexpected commands based on submodule configuration.
