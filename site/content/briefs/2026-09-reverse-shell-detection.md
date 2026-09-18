---
title: Detection of Reverse Shell Activity via Shell Command-Line Arguments
slug: 2026-09-reverse-shell-detection
description: This brief outlines detection logic for identifying reverse shell activity on Unix-like systems by monitoring shell processes for suspicious command-line network device redirection.
date: "2026-09-18T19:16:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - c2
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule identifies commands that are potentially related to reverse shell activities using shell applications.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1095
    technique_name: Non-Application Layer Protocol
    evidence: Identifies the execution of a shell process with suspicious arguments which may be indicative of reverse shell activity.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_revershell_via_shell_cmd.toml
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
rules:
  - title: Detect Suspicious Reverse Shell Activity via Shell
    description: Detects shell process execution with command-line arguments involving /dev/tcp or /dev/udp, commonly used for reverse shell connections.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1095
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to detect reverse shell attempts.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief.
  hunt_leads:
    - lead: Search for shell processes containing /dev/tcp or /dev/udp in logs.
      technique_id: T1059
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly documents this pattern as malicious.
  mitigation_plan:
    - priority: medium
      action: Implement egress filtering on firewalls to restrict unexpected outbound connections from servers.
      owner: Network Security
      addresses: T1095
      evidence: Reverse shells require an external listener.
---

Reverse shells are a primary post-exploitation technique used by attackers to gain remote command execution on compromised hosts. By redirecting a system's standard input, output, and error streams to an external network listener, attackers bypass typical ingress firewalls. This activity is frequently observed following successful vulnerability exploitation, malware execution, or manual adversary persistence.

The provided detection logic focuses on shell interpreters (sh, bash, zsh, dash) using specific device file paths (/dev/tcp, /dev/udp) or zsh-specific network modules to initiate outbound network connections. This technique is often used because it requires no external binaries, relying solely on built-in shell features to establish a command-and-control channel. Defenders should focus on identifying child processes or shell sessions that exhibit this behavior, excluding known benign local automation.

## Impact

Successful reverse shell execution grants attackers an interactive command prompt on the target host. This allows for lateral movement, data exfiltration, and the execution of further payloads. If left undetected, this allows attackers to maintain long-term access, potentially leading to widespread compromise of internal networks depending on the privileges of the shell process.

## Recommendation

Prioritize the deployment of behavioral detection for shell processes attempting to utilize local device files for network communication.

- Deploy the provided Sigma rule to your EDR or SIEM telemetry ingestion pipeline.
- Tune the rule by white-listing specific, verified internal automation paths that legitimately interact with internal infrastructure via /dev/tcp.
- Investigate any hits by reviewing the parent process lineage and searching for subsequent post-exploitation behavior like credential dumping or privilege escalation attempts.
- Ensure endpoint logging (Auditbeat or Elastic Defend) is configured to capture full command-line arguments to maintain visibility into these process arguments.
