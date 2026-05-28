---
title: Potential Privilege Escalation via unshare and UID Change
slug: 2026-05-privesc-unshare-uid
description: This rule detects potential privilege escalation attempts on Linux systems by monitoring the use of `unshare` with user namespace-related arguments followed by a UID change to root, indicating a transition to root and a potential local privilege escalation.
date: "2026-05-28T16:22:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - threat-detection
  - linux
vendors:
  - Elastic
products:
  - Elastic Defend
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability
  - https://twitter.com/liadeliyahu/status/1684841527959273472
  - https://attack.mitre.org/techniques/T1068/
  - https://attack.mitre.org/techniques/T1548/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: Potential Privilege Escalation via unshare and UID Change
    description: Detects suspicious use of unshare to create a user namespace context followed by a UID change event indicating a transition to root.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1548
    data_sources:
      - process_creation
      - linux
  - title: Potential Privilege Escalation via unshare with specific arguments
    description: Detects suspicious use of unshare command with specific arguments often used in privilege escalation exploits.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1548
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies potentially suspicious use of the `unshare` command, a utility used to create new namespaces, followed by a UID change to root (UID 0) on Linux systems. Adversaries may leverage `unshare`-based primitives as part of local privilege escalation chains. The rule specifically looks for scenarios where a non-root user executes `unshare` with user namespace related arguments (such as `-r`, `-rm`, `-m`, `-U`, or `--user`) and a subsequent `uid_change` event indicating the user has transitioned to root. This pattern can indicate a successful local privilege escalation attempt. This rule is intentionally generic to surface multiple local privilege escalation patterns beyond a single CVE.

## Attack Chain

1. A non-root user executes the `unshare` command.
2. The `unshare` command is executed with arguments indicating the creation of a user namespace (e.g., `-r`, `-rm`, `-m`, `-U`, `--user`).
3. The system creates a new user namespace as requested by the `unshare` command.
4. Within the new user namespace, the attacker attempts to change the user ID (UID).
5. The UID is successfully changed to 0, indicating root privileges within the namespace.
6. The process attempts to perform privileged actions within the new user namespace.
7. The attacker exploits the elevated privileges to potentially access sensitive data or execute arbitrary code.

## Impact

Successful exploitation can lead to complete system compromise, allowing attackers to install malware, modify system configurations, access sensitive data, or move laterally within the network. The potential impact ranges from data breaches and service disruption to complete system takeover, impacting confidentiality, integrity, and availability.

## Recommendation

- Deploy the Sigma rule "Potential Privilege Escalation via unshare and UID Change" to your SIEM and tune for your environment to detect the described behavior.
- Enable Elastic Defend integration for endpoint data collection to ensure the required logs are available for the Sigma rule.
- Review the process tree of processes triggering the detection, specifically the parent process of `unshare`, to identify the origin of the command execution as described in the "Triage and Analysis" section.
- Investigate other host signals around the same time as the `unshare` and `uid_change` events for any other suspicious activity, such as suspicious downloads or execution of unusual binaries as described in the "Triage and Analysis" section.
