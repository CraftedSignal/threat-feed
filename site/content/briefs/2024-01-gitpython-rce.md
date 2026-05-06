---
title: GitPython config_writer().set_value() Newline Injection RCE
slug: 2024-01-gitpython-rce
description: A newline injection vulnerability in GitPython's `config_writer().set_value()` function enables remote code execution by manipulating the `core.hooksPath` Git configuration.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - newline injection
  - remote code execution
  - gitpython
  - config poisoning
vendors:
  - gitpython
products:
  - GitPython (<= 3.1.48)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://github.com/advisories/GHSA-v87r-6q3f-2j67
rules:
  - title: Detect Git config hooksPath modification
    description: Detects attempts to modify the core.hooksPath setting in the .git/config file, which can lead to arbitrary code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - file_event
      - linux
  - title: Suspicious Git Hook Execution
    description: Detects execution of git hooks from unusual or attacker controlled locations.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A newline injection vulnerability exists in GitPython's `config_writer().set_value()` function, allowing attackers to achieve remote code execution. The vulnerability occurs because `set_value()` does not validate for newlines before passing values to Python's `configparser`. GitPython's writer converts embedded newlines into continuation lines, which Git still interprets as valid configuration. An attacker can inject a `core.hooksPath` configuration, causing Git to execute scripts from an attacker-controlled path whenever hooks are invoked. Discovered during an audit of MLRun's `project.push()` method, the vulnerability is triggered when `author_name` or `author_email` are passed to `config_writer().set_value()` without sanitization. This affects GitPython versions up to 3.1.48, git 2.39+.

## Attack Chain

1.  An attacker crafts a malicious input string containing a newline character followed by a `[core]` section and `hooksPath` setting.
2.  The malicious string is passed as either the `author_name` or `author_email` parameter to an application using GitPython.
3.  The application calls `config_writer().set_value()` with the attacker-controlled input, writing the malicious configuration to the `.git/config` file.
4.  GitPython converts the embedded newline into an indented continuation line but still writes it to the config.
5.  Git interprets the injected `[core]` stanza as a valid section header, thus setting the `core.hooksPath` to the attacker-specified path.
6.  A Git operation that invokes hooks (e.g., commit, merge, checkout) is triggered.
7.  Git executes the scripts located in the attacker-controlled `hooksPath`.
8.  The attacker gains arbitrary code execution on the system.

## Impact

Successful exploitation leads to persistent repository configuration poisoning. In multi-user environments, one user can poison a shared repository's `.git/config`, causing the attacker's hooks to run during subsequent Git operations by other users. The impact on single-user deployments depends on whether the application automatically invokes Git hooks. This vulnerability, now identified as CVE-2026-44244, can lead to privilege escalation and arbitrary code execution.

## Recommendation

*   Deploy the Sigma rule `Detect Git config hooksPath modification` to identify attempts to modify the `core.hooksPath` setting in the `.git/config` file.
*   Audit all calls to `config_writer().set_value()` in your codebase, especially where user-supplied input is used, as suggested in the overview.
*   Upgrade to a patched version of GitPython that raises an error on CR, LF, or NUL in config values, as described in the remediation section.
*   Monitor process creation events for the execution of scripts from unusual or unexpected paths specified in the `core.hooksPath` using the rule `Suspicious Git Hook Execution`.
