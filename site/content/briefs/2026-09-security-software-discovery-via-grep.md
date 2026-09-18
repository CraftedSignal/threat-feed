---
title: Detection of Security Software Discovery via Grep on macOS and Linux
slug: 2026-09-security-software-discovery-via-grep
description: Attackers utilize standard command-line tools like grep and pgrep to enumerate installed security software on macOS and Linux, enabling situational awareness for post-compromise activity.
date: "2026-09-18T19:13:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - macos
  - linux
  - e-dr
  - reconnaissance
affected_os:
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1518
    technique_name: Software Discovery
    evidence: Identifies the use of the grep command to discover known third-party macOS and Linux security tools, such as Antivirus or Host Firewall details.
    confidence_band: high
rules:
  - title: Security Software Discovery via Grep
    description: Identifies the use of grep, egrep, or pgrep to discover known macOS and Linux security tools.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1518.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Security Software Discovery via Grep detection rule.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit rule logic for detection.
  hunt_leads:
    - lead: Search for grep/egrep/pgrep commands occurring in short successions with security-related keywords.
      technique_id: T1518.001
      data_needed:
        - Process command line arguments
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source defines grep as a utility used for discovery.
  mitigation_plan:
    - priority: medium
      action: Review and restrict shell execution permissions for non-privileged users.
      owner: IT Operations
      addresses: T1518.001
      evidence: Source mentions limiting discovery as a post-compromise prevention step.
---

Post-compromise activity frequently involves situational awareness, where attackers attempt to identify the security posture of an infected host. On macOS and Linux environments, this is often achieved by searching process lists or security software configuration files for indicators of known antivirus, EDR, or firewall solutions. The use of native utilities like `grep`, `egrep`, and `pgrep` to filter for common security tool names (e.g., ESET, Sophos, SentinelOne, McAfee) allows an attacker to tailor their next steps, such as disabling agents, using bypasses, or choosing to abandon the host entirely. 

Defenders must differentiate between legitimate administrative maintenance, patch verification, and malicious reconnaissance. Because security software discovery is a common precursor to more damaging actions, this behavior should trigger investigations into the parent process tree, account behavior, and recent system changes.

## Attack Chain

1. An attacker gains initial access to a macOS or Linux host via an exploit or stolen credentials.
2. The attacker establishes a foothold and performs internal reconnaissance.
3. The attacker identifies the OS and common installation paths for security software.
4. The attacker executes `grep`, `egrep`, or `pgrep` to query logs, configuration files, or the process list for signatures of security tools (e.g., "Little Snitch", "kav", "sophos", "falcond").
5. The utility returns matches confirming the presence and potentially the version of security software.
6. Based on the output, the attacker proceeds to disable or circumvent the identified security controls.
7. The attacker moves to the final objective, such as data exfiltration or deploying ransomware.

## Impact

Successful security software discovery provides attackers with the necessary intelligence to evade detection, disable protective measures, and persist within the network. This activity significantly increases the probability of successful data theft or system destruction by allowing attackers to tailor their payloads to the specific defensive environment.

## Recommendation

- Deploy the provided detection rules to monitor for `grep` and `pgrep` commands targeting security software keywords.
- Investigate the parent process tree when these utilities are executed by non-root users, as this is a high-confidence indicator of reconnaissance.
- Baseline administrative scripts and maintenance tasks to tune out false positives originating from known paths like `/opt/McAfee/` or management frameworks.
- Isolate systems showing evidence of successful security software discovery to prevent further movement.
