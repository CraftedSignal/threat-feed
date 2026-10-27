---
brief_id: brief-2026-06-phoenixstorybook-rce
event_id: brief-2026-06-phoenixstorybook-rce
revision: 1
activity_at: "2026-06-14T13:33:49Z"
title: Critical Unauthenticated RCE in PhoenixStorybook via HEEx Template Injection (CVE-2026-8467)
slug: 2026-06-phoenixstorybook-rce
description: A critical unauthenticated remote code execution vulnerability (CVE-2026-8467) in Phenix Digital's `phoenix_storybook` versions 0.5.0 through 1.0.x allows attackers to inject arbitrary Elixir code via unsanitized WebSocket input, leading to OS command execution.
date: "2026-06-14T13:33:49Z"
lastmod: "2026-10-27T18:15:36Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:phenix_digital:phoenix_storybook:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=60FB9B88-DD24-5D67-8993-58795FA94321&utm_source=rss&utm_medium=rss
tags:
  - rce
  - web-vulnerability
  - elixir
  - phoenix
  - websocket
  - template-injection
  - linux
vendors:
  - Phenix Digital
products:
  - phoenix_storybook (>= 0.5.0, < 1.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.006
    subtechnique_name: Python
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.005
    subtechnique_name: Visual Basic
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
cves:
  - id: CVE-2026-8467
    epss: 0.02111
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-55hg-8qxv-qj4p
  - https://github.com/phenixdigital/phoenix_storybook/commit/e35379dfe2ef1a71b141899e36f431017c55265d
  - https://github.com/phenixdigital/phoenix_storybook/commit/56ab8464d4375fa52db806148a06cce126ad481d
  - CVE-2026-8467
  - https://sploitus.com/exploit?id=60FB9B88-DD24-5D67-8993-58795FA94321&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-8467 Exploitation - Suspicious Child Process from beam.smp
    description: Detects exploitation of CVE-2026-8467 by monitoring for suspicious child processes spawned directly by the 'beam.smp' (Erlang VM) process, indicative of arbitrary command execution via Elixir's System.cmd/2 function.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
      - T1071.001
    data_sources:
      - process_creation
      - linux
  - title: Detects Suspicious Script Interpreter Execution with Web-Related Parameters
    description: Detects the execution of common scripting interpreters (bash, python, curl, etc.) with command-line arguments typically associated with web-based RCE, such as downloading files from remote URLs or interacting with network streams, potentially indicating post-exploitation activity or web shell deployment, including from CVE-2026-8467.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
      - persistence
    techniques:
      - T1059
      - T1543.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
updates:
  - at: "2026-10-27T18:15:36Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=60FB9B88-DD24-5D67-8993-58795FA94321&utm_source=rss&utm_medium=rss
---

A critical unauthenticated remote code execution vulnerability, identified as CVE-2026-8467, affects Phenix Digital's `phoenix_storybook` library, specifically versions from 0.5.0 up to, but not including, 1.1.0. This flaw lies within the `phoenix_storybook` playground's handling of HEEx templates, allowing unauthenticated attackers to inject arbitrary Elixir code into a server-side template. The vulnerability leverages unsanitized user-controlled attributes passed via WebSocket connections, leading to direct code execution with full `Kernel` access. This permits attackers to execute arbitrary operating system commands on the compromised server. The vulnerability requires no authentication or special configuration, making it highly exploitable, especially if the storybook interface is exposed publicly. This poses a severe risk to organizations using affected versions, enabling complete system compromise.

## Attack Chain

1. **Initial Access**: An unauthenticated attacker identifies a `phoenix_storybook` instance running versions between 0.5.0 and 1.0.x (e.g., at `/storybook/core_components/button`) exposed publicly or internally.
2. **WebSocket Connection**: The attacker establishes an unauthenticated WebSocket connection to the Phoenix LiveView channel associated with the identified story's Playground tab.
3. **Malicious Input**: The attacker sends a `psb-assign` event via the WebSocket. This event contains a crafted attribute value designed to escape the HEEx attribute context and embed arbitrary Elixir expressions.
4. **Unsanitized Interpolation**: The `PhoenixStorybook.Story.PlaygroundPreviewLive` component accepts the arbitrary attribute names and values. The `ComponentRenderer.attributes_markup/1` function then directly interpolates this unsanitized binary value into a HEEx template string (e.g., `~s|#{name}="#{val}"|`).
5. **Code Injection**: The crafted attribute value uses Elixir's interpolation syntax (e.g., `foo" injected={EXPR} bar="`) to inject a malicious Elixir expression (`EXPR`) within the HEEx template, bypassing any escaping.
6. **Unsandboxed Compilation**: The server compiles the resulting HEEx string (containing the injected Elixir code) via `EEx.compile_string/2`.
7. **Unsandboxed Evaluation**: The compiled code is then evaluated using `Code.eval_quoted_with_env/3` with full `Kernel` imports and no sandboxing, allowing the malicious Elixir expression to execute.
8. **Remote Code Execution**: The injected Elixir expression, typically a `System.cmd/2` call (e.g., `System.cmd("bash", ["-c", "whoami"])`), executes arbitrary operating system commands on the server with the privileges of the Elixir application process, leading to full system compromise.

## Impact

This pre-authentication remote code execution vulnerability allows any unauthenticated user who can reach the `phoenix_storybook` endpoint to execute arbitrary operating system commands. If the storybook is publicly exposed, internet-facing systems are vulnerable to complete compromise. Successful exploitation grants the attacker full control over the affected server, enabling data exfiltration, deployment of further malware, persistence mechanisms, or integration into botnets. All versions of `phoenix_storybook` from 0.5.0 before 1.1.0 are vulnerable, potentially impacting a wide range of Elixir applications leveraging this library.

## Recommendation

*   Immediately patch `phoenix_storybook` to version 1.1.0 or later to address CVE-2026-8467.
*   Deploy the provided Sigma rules to your SIEM and tune for your environment to detect post-exploitation activity resulting from CVE-2026-8467.
*   Implement strict network segmentation to restrict access to development/storybook environments, ensuring they are not publicly exposed.
*   Enable comprehensive `process_creation` logging on Linux servers running Elixir applications, specifically monitoring for unusual child processes spawned by the `beam.smp` process.
