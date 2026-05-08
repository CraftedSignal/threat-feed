---
title: Potential Privilege Escalation via unshare and UID Change
slug: 2024-01-unshare-privesc
description: This rule detects potential privilege escalation attempts on Linux systems by identifying suspicious use of the `unshare` command to create user namespaces followed by a UID change to root, indicative of local privilege escalation.
date: "2024-01-09T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - linux
  - unshare
  - namespace
vendors:
  - Elastic
  - Ubuntu
products:
  - Elastic Defend
  - Elastic Endpoint
affected_os:
  - Linux
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
rules:
  - title: Detect Potential Privilege Escalation via unshare and UID Change
    description: Detects potential privilege escalation attempts by identifying the execution of `unshare` with user namespace arguments followed by a UID change to root.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect unshare Execution from Suspicious Locations
    description: Detects `unshare` execution from user-writable directories like /tmp or /dev/shm.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies potential privilege escalation attempts on Linux systems by monitoring the use of the `unshare` command and subsequent UID changes to root. The `unshare` command is used to create new namespaces, including user namespaces, which can be leveraged in exploit chains. Attackers may use `unshare` with user namespace flags as a preliminary step before escalating privileges to root. This behavior can indicate successful exploitation of vulnerabilities, such as those related to OverlayFS, or other local privilege escalation techniques. This detection is intentionally generic to surface multiple local privilege escalation patterns beyond a single CVE. The rule focuses on detecting a sequence of events where a non-root user executes `unshare` with user-namespace related arguments followed by a UID change event indicating the user has become root.

## Attack Chain

1. A non-root user executes the `unshare` command with arguments indicating the creation of a new user namespace (e.g., `-U`, `--user`, `-r`, `-rm`, `m`).
2. The `unshare` command creates a new user namespace context for the process.
3. Within the newly created namespace, the attacker attempts to change the user ID (UID) to 0 (root).
4. The system logs a `uid_change` event, indicating that the user's UID has been changed to 0 within the namespace.
5. The attacker executes further commands as root within the new namespace.
6. These commands may involve exploiting vulnerabilities, modifying system files, or installing malicious software.
7. The attacker may attempt to escape the namespace to gain root privileges on the host system.
8. The final objective is to gain persistent root access to the system, allowing for complete control and potential data exfiltration or system compromise.

## Impact

Successful exploitation can lead to complete system compromise, allowing the attacker to perform any action with root privileges. This can result in data theft, system disruption, or the installation of backdoors for persistent access. The number of victims can vary depending on the scope of the attack, but even a single successful privilege escalation can have severe consequences. Targeted sectors are broad, including any Linux-based system where unprivileged users have access to the `unshare` command, such as cloud workloads and traditional endpoints.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious `unshare` usage followed by UID changes (`Potential Privilege Escalation via unshare and UID Change`).
*   Investigate any detected instances of `unshare` usage with user namespace arguments and subsequent UID changes to root, as described in the rule description.
*   Review and restrict the use of `unshare` and user namespaces if not required in your environment to mitigate the risk of privilege escalation.
*   Enable Elastic Defend integration to collect the necessary process and event data required for the Sigma rule to function effectively (Elastic Defend integration).
*   Monitor process execution for commands run after the `uid_change` event to identify potentially malicious activities.
