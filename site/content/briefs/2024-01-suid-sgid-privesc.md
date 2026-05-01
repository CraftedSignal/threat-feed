---
title: Potential Privilege Escalation via SUID/SGID Abuse on Linux
slug: 2024-01-suid-sgid-privesc
description: This rule detects potential privilege escalation attempts on Linux systems by identifying processes running with root privileges but initiated by non-root users, indicative of SUID/SGID abuse.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - persistence
  - suid
  - sgid
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://gtfobins.github.io/#+suid
  - https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
rules:
  - title: Privilege Escalation via SUID/SGID Binary Execution
    description: Detects execution of SUID/SGID binaries by non-root users, potentially leading to privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
    data_sources:
      - process_creation
      - linux
  - title: Suspicious SUID/SGID Binary Modification
    description: Detects modification of SUID/SGID bits on binaries, which might indicate an attacker preparing for privilege escalation.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This detection rule, sourced from Elastic, identifies instances where a process executes with root privileges (UID/GID 0) while the real user/group ID is non-zero. This condition suggests that the process has been granted SUID/SGID permissions, potentially allowing it to run with elevated privileges. Attackers may exploit such misconfigurations to escalate their privileges to root or establish persistence mechanisms. The rule focuses on Linux systems and leverages Elastic Defend data to identify such events. The initial publication date of the rule was in June 2024, with updates made as recently as May 2026. This type of misconfiguration can lead to significant security breaches.

## Attack Chain

1.  A user (non-root) executes a binary that has the SUID or SGID bit set.
2.  The system checks the permissions of the executable and identifies the SUID/SGID bit.
3.  The process spawns with the effective UID/GID set to the owner/group of the executable file (typically root).
4.  The process attempts to perform actions that require elevated privileges.
5.  If the SUID/SGID binary is vulnerable, the attacker can leverage it to execute arbitrary commands as root.
6.  The attacker escalates privileges to root, gaining full control over the system.
7.  The attacker installs a backdoor for persistent access.
8.  The attacker performs malicious activities, such as data exfiltration or system compromise.

## Impact

Successful exploitation of SUID/SGID misconfigurations can grant an attacker root-level access to a Linux system. This can lead to complete system compromise, including data theft, installation of malware, and the potential for lateral movement to other systems on the network. A single compromised system can be leveraged to attack other internal assets.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect potential SUID/SGID exploitation (see the `rules` section).
*   Review the SUID/SGID binaries identified by the rule and verify their configurations to ensure they are correctly set and necessary.
*   Implement enhanced monitoring and logging for SUID/SGID execution attempts to detect and respond to similar threats in the future (Data Source: Elastic Defend).
*   Consider implementing stricter access controls and reducing the number of SUID/SGID binaries on the system to minimize the attack surface.
*   Investigate the parent process of the flagged binaries to determine the origin of the execution and whether it aligns with expected behavior.
