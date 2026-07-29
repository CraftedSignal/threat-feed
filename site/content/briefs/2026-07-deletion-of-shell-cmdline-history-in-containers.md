---
title: Deletion of Shell Command-Line History in Containers
slug: 2026-07-deletion-of-shell-cmdline-history-in-containers
description: An unidentified adversary is leveraging common shell commands to delete or disable command-line history files within Linux containers, aiming to evade detection by obscuring their activities during reconnaissance or credential access.
date: "2026-07-29T12:34:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - container
  - linux
  - threat-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: This rule detects the deletion of shell command-line history files inside a container. Adversaries may delete these files to cover their tracks or evade detection. An attacker uses kubectl exec to open an interactive bash shell in a running pod, then symlinks /root/.bash_history to /dev/null to prevent future commands from being recorded.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/defense_evasion_deletion_of_shell_cmdline_history.toml
rules:
  - title: Detect Container Shell History File Deletion
    description: Detects explicit deletion of common shell command-line history files within Linux containers, indicating defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070
      - T1070.003
    data_sources:
      - file_event
      - linux
  - title: Detect Container Shell History Disabling or Clearing Commands
    description: Detects process execution patterns used to clear or disable shell command-line history in Linux containers, indicative of defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070
      - T1070.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Unidentified adversaries are actively targeting Linux containers by deleting or disabling shell command-line history files. This tactic, often observed after initial access has been established (e.g., via `kubectl exec`), aims to erase forensic evidence and impede incident investigations. Attackers typically modify or remove files like `.bash_history`, `.sh_history`, or `.zsh_history`, or manipulate shell environment variables and functions (e.g., `HISTFILE=/dev/null`, `unset HISTFILE`, `history -c`) to prevent recording subsequent malicious commands. This technique is a crucial defense evasion mechanism that allows threat actors to conduct reconnaissance, elevate privileges, or exfiltrate data without leaving a clear trail of their actions within the compromised container, making post-compromise analysis significantly more challenging for defenders.

## Attack Chain

1. An attacker gains initial access to a Kubernetes cluster, potentially through compromised credentials or exposed services.
2. The attacker utilizes `kubectl exec` to establish an interactive shell session within a target container, gaining a foothold in the runtime environment.
3. Inside the container, the attacker executes reconnaissance commands (e.g., `ls -la /`, `cat /etc/passwd`, `env`) to understand the environment and identify sensitive data or credentials.
4. To avoid detection, the attacker modifies shell settings or files to prevent command history logging, such as using `ln -sf /dev/null ~/.bash_history` or `export HISTFILE=/dev/null`.
5. With history suppressed, the attacker proceeds with further malicious activities, such as credential access (e.g., stealing service account tokens), lateral movement, or data staging.
6. The attacker may then exfiltrate sensitive data from the compromised container or establish persistence mechanisms for future access.

## Impact

Successful execution of this technique significantly impairs an organization's ability to detect, investigate, and respond to container compromises. By erasing command history, attackers obscure their actions, making it difficult to determine the scope of compromise, the tools used, and the data accessed. This lack of visibility can lead to prolonged dwell times, undetected lateral movement across the container environment, and potential for severe data breaches or disruption of critical services. Without command history, forensic analysis becomes reliant on less granular logs, potentially delaying remediation efforts and increasing the overall cost of an incident.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect attempts to delete or disable shell history files.
* Implement robust container runtime security monitoring to capture `process_creation` and `file_event` logs, enabling activation of the provided Sigma rules.
* Restrict `kubectl exec` and `kubectl attach` permissions via Kubernetes Role-Based Access Control (RBAC) to only authorized break-glass roles.
* Enforce admission controls in Kubernetes to block container images or init scripts that unset HISTFILE or link `~/.bash_history` to `/dev/null`.
* Review Kubernetes audit logs for `exec/attach` actions, correlating with container telemetry to identify suspicious activity.
