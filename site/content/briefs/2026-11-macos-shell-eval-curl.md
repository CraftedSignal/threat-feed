---
brief_id: brief-2026-11-17-macos-shell-eval-curl
event_id: brief-2026-11-17-macos-shell-eval-curl
revision: 1
activity_at: "2026-11-17T14:58:01Z"
title: 'macOS: Shell evaluation of curl-downloaded content'
slug: 2026-11-macos-shell-eval-curl
description: Threat actors on macOS use shell one-liners to fetch remote content via 'curl' and pass the output directly to the 'eval' command, allowing code to execute in memory without writing artifacts to disk.
date: "2026-11-17T14:58:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: macOS loaders and stagers (for example WizardUpdate/UpdateAgent, adware droppers and infostealer installers) use this pattern to pull their next stage.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Detects a shell that downloads content with curl and passes it to eval, either directly or through a variable assignment.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/execution_shell_eval_of_curl_downloaded_content.toml
  - https://www.microsoft.com/security/blog/2022/02/02/the-evolution-of-a-mac-trojan-updateagents-progression/
rules:
  - title: Shell Evaluated Curl Downloaded Content
    description: Detects a shell that downloads content with curl and passes it to eval, either directly or through a variable assignment. Downloading a script and evaluating it in memory avoids writing the payload to disk.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1105
    data_sources:
      - process_creation
      - macos
rules_count: 1
---

## Overview

Malicious actors use memory-only execution patterns on macOS to avoid writing payloads to disk. A common technique involves using shell interpreters (bash, dash, sh, zsh, ksh) to fetch remote content via `curl` and pass the output directly to the `eval` command, either directly or through a variable assignment. This pattern is used by macOS loaders and stagers, such as UpdateAgent (also referred to as WizardUpdate), adware droppers, and infostealer installers to retrieve and run their next stage. Legitimate developer tooling, AI coding agents, and management agents also utilize this pattern for API testing or configuration retrieval.

## Attack Chain

1. Execution of a shell command that retrieves content using `curl`.
2. The `curl` output is captured in a variable or piped directly to the command interpreter.
3. The `eval` command interprets the downloaded data as executable code within the shell's memory space.
4. The payload executes in memory.

## Impact

In-memory execution allows attackers to retrieve and run secondary payloads while avoiding writing artifacts to the local file system.

## Recommendation

- Monitor shell command-line patterns for sequences containing both `curl` and `eval`.
- Review `process.command_line` to identify the URL being retrieved and whether the evaluated content comes directly from `curl` or from a variable populated by `curl`.
- Examine `process.parent.executable`, `process.parent.command_line`, and `process.Ext.effective_parent.executable` to determine what launched the shell.
- Check the reputation of the domain or IP in the curl request (e.g., raw IP, newly registered domain, paste site or file-sharing service).
- Look for follow-on activity such as additional downloads, `xattr` quarantine removal, LaunchAgent/LaunchDaemon creation, or credential and browser data access.
- Create exceptions for known legitimate internal administration scripts, developer tools, and vendor-signed MDM agents.
