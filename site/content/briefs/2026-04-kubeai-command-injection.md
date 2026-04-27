---
title: KubeAI OS Command Injection via Model URL in Ollama Engine Startup Probe
slug: 2026-04-kubeai-command-injection
description: The KubeAI project is vulnerable to OS command injection because the `ollamaStartupProbeScript()` function constructs a shell command string using `fmt.Sprintf` with unsanitized model URL components (`ref`, `modelParam`), which is then executed via `bash -c` as a Kubernetes startup probe, allowing arbitrary command execution inside model server pods by attackers with the ability to create or update `Model` custom resources.
date: "2026-04-01T23:22:43Z"
severities:
  - high
tags:
  - kubeai
  - command-injection
  - kubernetes
  - cloud
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-324q-cwx9-7crr
rules:
  - title: Detect KubeAI Model Resource Command Injection
    description: Detects potentially malicious Model resources with command injection attempts in the URL field.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - auditd
      - kubernetes
  - title: Detect Outbound Connections from KubeAI Pods after Model Creation
    description: Detects outbound connections from KubeAI pods immediately after a new model is deployed, which could indicate data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

KubeAI versions 0.23.1 and earlier are vulnerable to an OS command injection flaw in the Ollama engine's startup probe. The vulnerability stems from the `ollamaStartupProbeScript()` function, which constructs a shell command using `fmt.Sprintf` with unsanitized model URL components (`ref` and `modelParam`). These components are extracted from the Model custom resource URL. An attacker who can create or update `Model` custom resources can inject arbitrary shell commands, which are then executed…
