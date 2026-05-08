---
title: GitPython config_writer() Newline Injection Bypasses CVE-2026-42215 Patch
slug: 2026-05-gitpython-newline-injection
description: An incomplete patch for CVE-2026-42215 in GitPython allows newline injection in the section parameter of the config_writer() function, enabling arbitrary .git/config modification and remote code execution via core.hooksPath.
date: "2026-05-08T23:19:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - gitpython
  - newline-injection
  - rce
  - code-injection
vendors:
  - gitpython
products:
  - GitPython (<= 3.1.49)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
cves:
  - id: CVE-2026-42215
    cvss: 8.8
    epss: 0.00091
references:
  - https://github.com/advisories/GHSA-mv93-w799-cj2w
rules:
  - title: Detect Git Hook Execution from Suspicious Path
    description: Detects execution of git hooks from directories other than the standard .git/hooks directory, indicating potential exploitation of core.hooksPath injection vulnerabilities like CVE-2026-42215 bypass
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Git Config Modification with Suspicious Section Injection
    description: Detects modifications to the .git/config file that involve injecting new sections, potentially exploiting newline injection vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

GitPython versions 3.1.49 and earlier are vulnerable to newline injection in the `config_writer()` function. The patch for CVE-2026-42215, intended to prevent arbitrary configuration modification and RCE, only validates the `value` parameter of the `set_value()` function, neglecting to validate the `section` and `option` parameters. This oversight allows an attacker to inject newline characters into the `section` parameter, enabling the writing of arbitrary section headers into the `.git/config` file. By forging a `[core]` section with a malicious `hooksPath`, attackers can achieve remote code execution when a git hook is triggered. This vulnerability allows a bypass of the intended protection provided by the CVE-2026-42215 patch and effectively re-introduces the original vulnerability.

## Attack Chain

1.  Attacker gains control over a GitPython application or code that uses the `config_writer()` function.
2.  The attacker crafts a malicious `section` string containing newline characters (e.g., `user]\n[core`).
3.  The attacker calls `config_writer().set_value()` with the crafted `section`, the `option` set to `hooksPath`, and a `value` pointing to an attacker-controlled directory (e.g., `/tmp/evil_hooks`).
4.  The `set_value()` function writes the crafted `section` string (e.g., `[user]\n[core]\n`) into the `.git/config` file, creating a new `[core]` section or modifying an existing one.
5.  The `hooksPath` option within the injected `[core]` section is set to the attacker-controlled directory.
6.  The attacker places a malicious script (e.g., `pre-commit`) within the attacker-controlled directory and makes it executable.
7.  A git hook is triggered (e.g., by running `git commit`).
8.  The malicious script is executed, resulting in remote code execution.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the target system, potentially leading to full system compromise. The impact is similar to CVE-2026-42215. This bypass is particularly damaging as organizations may believe they are protected by patching to version 3.1.49, while they remain vulnerable. There is no information regarding the number of victims or specific sectors targeted, but any application using a vulnerable version of GitPython is at risk.

## Recommendation

*   Apply input validation to the `section` and `option` parameters of the `set_value()` function in `git/config.py` to prevent newline injection.
*   Upgrade GitPython to a version beyond 3.1.49 if a new version addressing this bypass is released.
*   Monitor process creation events for execution of scripts from unusual or attacker-controlled directories defined in `core.hooksPath`, using a Sigma rule such as the one provided below.
*   Regularly audit `.git/config` files for unexpected or suspicious configurations, especially for modifications to `core.hooksPath`.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
