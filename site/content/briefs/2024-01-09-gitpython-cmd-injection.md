---
title: GitPython Command Injection Vulnerability
slug: 2024-01-09-gitpython-cmd-injection
description: GitPython versions 3.1.30 through 3.1.46 are vulnerable to command injection by passing attacker-controlled kwargs into `Repo.clone_from()`, `Remote.fetch()`, `Remote.pull()`, or `Remote.push()`, leading to arbitrary command execution due to bypassed safety checks.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - gitpython
  - vulnerability
vendors:
  - pip
products:
  - GitPython (3.1.30-3.1.46)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-rpm5-65cw-6hj4
rules:
  - title: Detect GitPython Kwarg Command Injection
    description: Detects potential command injection attempts via GitPython by identifying calls to Repo.clone_from, Remote.fetch, Remote.pull, or Remote.push with potentially malicious kwargs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
  - title: Detect GitPython Kwarg Command Injection via Modified Process Name
    description: Detects potential command injection attempts via GitPython by identifying calls to Repo.clone_from, Remote.fetch, Remote.pull, or Remote.push with potentially malicious kwargs when the python process name has been changed.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

GitPython, a library providing programmatic interaction with Git repositories, is susceptible to a command injection vulnerability in versions 3.1.30 to 3.1.46. The vulnerability stems from insufficient validation of keyword arguments (kwargs) passed to functions like `Repo.clone_from()`, `Remote.fetch()`, `Remote.pull()`, and `Remote.push()`. Specifically, when underscore-form kwargs (e.g., `upload_pack`) are used, they bypass the intended safety checks designed to prevent the execution of arbitrary commands via Git options like `--upload-pack`. This occurs because the validation logic only checks for hyphenated forms (e.g., `upload-pack`). Attackers can exploit this by injecting malicious commands through these kwargs, even when `allow_unsafe_options` is set to its default value of `False`. This issue was reported on April 25, 2026.

## Attack Chain

1. An attacker identifies a web application or system that uses GitPython to manage Git repositories.
2. The attacker finds an endpoint or function where they can control kwargs passed to `Repo.clone_from()`, `Remote.fetch()`, `Remote.pull()`, or `Remote.push()`.
3. The attacker crafts a malicious payload, using underscore-form kwargs such as `upload_pack` or `receive_pack`, setting their value to a command they want to execute (e.g., a shell script path or a direct command).
4. The application or system, using a vulnerable version of GitPython, receives these kwargs and bypasses the intended safety check.
5. GitPython's `Git.transform_kwarg()` method converts the underscore-form kwargs into their corresponding hyphenated Git options (e.g., `upload_pack` becomes `--upload-pack`).
6. The Git command is executed with the attacker-controlled option, leading to arbitrary command execution on the system.
7. The attacker gains unauthorized access, potentially stealing credentials, modifying repositories, or moving laterally within the network.

## Impact

Successful exploitation of this vulnerability can lead to severe consequences, especially in web applications, CI/CD systems, and automation tools that rely on GitPython for repository management. Attackers could steal SSH keys, API tokens, cloud credentials, or other sensitive information. They could also modify repositories, build outputs, or release artifacts, leading to supply chain attacks. In CI/CD environments, this vulnerability could enable lateral movement from worker nodes or compromise the entire automation infrastructure. The number of affected systems depends on the prevalence of vulnerable GitPython versions in exposed applications.

## Recommendation

*   Upgrade GitPython to version 3.1.47 or later to remediate the vulnerability (affected_products).
*   Review code that uses `Repo.clone_from()`, `Remote.fetch()`, `Remote.pull()`, or `Remote.push()` and ensure that kwargs are properly validated to prevent attacker-controlled input (references).
*   Implement input validation to block underscore-form kwargs such as `upload_pack` or `receive_pack` before they are passed to GitPython functions (references).
*   Deploy the Sigma rule `Detect GitPython Kwarg Command Injection` to identify potential exploitation attempts in application logs (rules).
