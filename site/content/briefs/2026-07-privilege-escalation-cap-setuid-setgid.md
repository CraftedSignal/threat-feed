---
title: Linux Privilege Escalation via CAP_SETUID/SETGID Capabilities
slug: 2026-07-privilege-escalation-cap-setuid-setgid
description: This brief details a Linux privilege escalation technique where attackers leverage misconfigurations in applications with CAP_SETUID or CAP_SETGID capabilities to elevate their privileges to root (UID/GID 0), enabling unauthorized system control and further malicious activities.
date: "2026-07-20T12:48:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - linux
  - capabilities
  - root-access
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Identifies instances where a process (granted CAP_SETUID and/or CAP_SETGID capabilities) is executed, after which the user's access is elevated to UID/GID 0 (root). Attackers may leverage a misconfiguration for exploitation in order to escalate their privileges to root.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: In Linux, the CAP_SETUID and CAP_SETGID capabilities allow a process to change its UID and GID, respectively, providing control over user and group identity management. Adversaries exploit misconfigurations to gain root access.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Adversaries exploit misconfigurations to gain root access. The detection rule identifies processes with these capabilities that elevate privileges to root, excluding benign scenarios, to flag potential misuse.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_suspicious_uid_guid_elevation.toml
---

This threat involves a Linux privilege escalation technique where attackers exploit misconfigurations related to the CAP_SETUID and CAP_SETGID capabilities. In Linux, these capabilities allow a process to change its User ID (UID) and Group ID (GID) respectively, which is critical for identity management. An adversary can leverage an application or system utility that has been granted these capabilities but is misconfigured, allowing them to execute code with elevated privileges. The detection focuses on identifying processes that are initiated with `CAP_SETUID` or `CAP_SETGID` capabilities, running under a non-root user, and subsequently change their effective UID or GID to 0 (root). This indicates a successful or attempted privilege escalation to gain full control over the compromised system. The technique is a common method for attackers to transition from initial access to a more persistent and controlling posture.

## Attack Chain

1. An attacker gains initial access to a Linux system, often as a low-privileged user.
2. The attacker identifies a misconfigured application or utility with `CAP_SETUID` or `CAP_SETGID` capabilities.
3. The attacker executes the identified process, which initially runs under the attacker's non-root user context.
4. Leveraging the misconfiguration or vulnerability within the capable process, the attacker manipulates it to change its effective UID or GID to 0 (root).
5. The system grants the process root privileges based on the successful UID/GID change, despite the initial execution context being non-root.
6. The attacker now has command execution capabilities as the root user through the context of the elevated process.
7. The attacker can then perform actions such as installing backdoors, creating new privileged accounts, or disabling security controls.
8. The final objective, such as data exfiltration or system destruction, is achieved with full administrative control.

## Impact

A successful privilege escalation to root via `CAP_SETUID`/`CAP_SETGID` capabilities grants the attacker complete control over the compromised Linux system. This includes the ability to access, modify, or delete any file, install or remove software, create or modify user accounts, disable security measures, and exfiltrate sensitive data without restriction. The impact extends to potential lateral movement to other systems, disruption of critical services, and establishment of persistent unauthorized access, severely compromising the integrity, confidentiality, and availability of affected assets.

## Recommendation

* Review system configurations to identify and correct any misconfigurations that may inadvertently grant `CAP_SETUID` or `CAP_SETGID` capabilities to unauthorized processes or scripts.
* Regularly audit `CAP_SETUID` and `CAP_SETGID` binaries on Linux systems to ensure only necessary and properly configured applications possess these capabilities.
* Implement host-based security monitoring using endpoint detection and response (EDR) solutions like Elastic Defend to log and alert on `process_creation` and `uid_change` events, especially those involving capability changes.
* Isolate any affected hosts immediately upon detection of suspicious privilege escalation activity to prevent further compromise or lateral movement.
* Revoke unnecessary `CAP_SETUID` and `CAP_SETGID` capabilities from processes that do not strictly require them, reducing the attack surface.
