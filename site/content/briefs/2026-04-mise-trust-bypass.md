---
title: Mise Trust Bypass Vulnerability via Malicious .mise.toml
slug: 2026-04-mise-trust-bypass
description: A vulnerability in mise allows an attacker who can place a malicious .mise.toml file in a repository to bypass trust checks and execute arbitrary code via `[env] _.source` due to improper loading of trust settings.
date: "2026-04-07T20:13:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mise
  - trust-bypass
  - code-execution
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
references:
  - https://github.com/advisories/GHSA-436v-8fw5-4mj8
rules:
  - title: Detect Mise Hook-Env with Dot Source
    description: Detects the execution of `mise hook-env` with a potentially malicious `.source` directive within the .mise.toml file, indicating a possible trust bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation by Mise
    description: Detects suspicious file creation, such as in /tmp, by the mise process, which could indicate arbitrary code execution following a trust bypass.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability exists in the mise tool (versions 2026.2.18 through 2026.4.5) where local project configuration files (.mise.toml) are loaded *before* trust checks are performed. This allows an attacker who can influence the contents of a repository (e.g., through a pull request or direct commit) to inject malicious configurations that bypass intended trust restrictions. Specifically, an attacker can set `trusted_config_paths = ["/"]` within a crafted .mise.toml, which effectively trusts all configuration files, including the malicious one. This bypass then permits the execution of dangerous directives, such as arbitrary shell commands via `[env] _.source`, leading to potential system compromise. This vulnerability undermines the security model of mise by subverting the trust mechanism designed to prevent unauthorized code execution.

## Attack Chain

1.  An attacker gains the ability to modify a repository containing a mise project. This could be via a compromised account, a malicious pull request, or other means.
2.  The attacker creates or modifies a `.mise.toml` file within the repository, adding the following lines:
    ```toml
    [settings]
    trusted_config_paths = ["/"]

    [env]
    _.source = ["./poc.sh"]
    ```
3.  The attacker creates or modifies a file `poc.sh` containing the malicious commands to be executed. For example:
    ```bash
    #!/usr/bin/env bash
    echo "Exploited!" > /tmp/pwned.txt
    ```
4.  A user clones the repository and navigates to the project directory.
5.  The user executes the command `mise hook-env -s bash --force`. This command is intended to set up the environment based on the `.mise.toml` configuration.
6.  Because `trusted_config_paths` is set to `/`, the `.mise.toml` file is considered trusted and the `[env] _.source` directive is executed.
7.  The `poc.sh` script is executed, resulting in arbitrary code execution. In this example, the `/tmp/pwned.txt` file is created containing "Exploited!".
8.  The attacker has achieved arbitrary code execution on the user's system.

## Impact

Successful exploitation allows an attacker to execute arbitrary code on the victim's machine. The number of potential victims is equal to the number of users who clone and use a repository containing the malicious `.mise.toml` file and are using a vulnerable version of `mise` (2026.2.18 - 2026.4.5). The impact ranges from data theft and system compromise to complete control of the affected system, depending on the commands executed by the attacker's script. Organizations using mise for environment management are particularly at risk.

## Recommendation

*   Upgrade to a patched version of `mise` greater than 2026.4.5 to address CVE-2026-35533.
*   Deploy the Sigma rule `Detect Mise Hook-Env with Dot Source` to identify potential exploitation attempts based on the `mise hook-env` command.
*   Monitor for the creation of unexpected files (e.g., in /tmp) after the execution of `mise hook-env` commands.
*   Implement code review processes to prevent the introduction of malicious `.mise.toml` files into repositories.
