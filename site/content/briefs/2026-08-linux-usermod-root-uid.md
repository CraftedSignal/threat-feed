---
title: Detection of Linux Privilege Escalation via UID 0 Assignment
slug: 2026-08-linux-usermod-root-uid
description: Attackers may assign a UID of 0 to a non-privileged user account using the 'usermod' utility to establish persistent root-level access on Linux systems.
date: "2026-08-07T15:19:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This approach can be used to bypass regular privilege escalation mechanisms, giving the attacker full control over the system while appearing as a regular user.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.001
    technique_name: Setuid and Setgid
    evidence: The following analytic detects the use of usermod to set a user's UID to 0. This functionally sets the user as a root user with full permissions.
    confidence_band: high
rules:
  - title: Detect Linux usermod UID 0 Assignment
    description: Detects the use of the usermod utility to assign a UID of 0, effectively granting root privileges to a non-root user.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1548.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Implement the Sigma rule to monitor for UID 0 assignments
      owner: Detection Engineering
      due: 48h
      evidence: High-risk indicator identified in source analytic
  mitigation_plan:
    - priority: medium_term
      action: Restrict sudo access and usermod binary execution to authorized administrators only
      owner: IT Operations
      addresses: T1548.001
      evidence: Hardening system administration processes
---

The 'usermod' utility is a standard Linux administrative tool used to modify existing user accounts. Attackers can leverage this utility to elevate a non-privileged account to root status by modifying the user's User ID (UID) to 0. In Linux systems, the UID 0 is reserved for the root user, granting full administrative privileges regardless of the username. 

This technique provides a stealthy method for privilege escalation and persistence. Because the account name may remain unchanged, it may bypass security controls or monitoring tools that track specific administrative usernames rather than observing the underlying UID modification. Legitimate administrative use of 'usermod' to assign UID 0 to a standard user is extremely rare, making this behavior a high-fidelity indicator of malicious activity or significant policy violation. Defenders should investigate the context of such commands immediately.

## Impact

Successful execution of this technique results in immediate privilege escalation to root-level access. This allows an attacker to maintain persistent, unrestricted access to the target host, modify system configuration, disable security tools, and access sensitive data. This technique facilitates further post-exploitation activities and poses a severe risk to system integrity.

## Recommendation

* Deploy the Sigma rule below to detect any instance of 'usermod' being used to assign UID 0.
* Establish an alert for any execution of the 'usermod' binary with the -u or --uid flags.
* Validate any detected activity against existing change management systems to identify authorized administrative actions.
* Enable Sysmon for Linux process-creation logging to ensure the command-line arguments are captured in your telemetry.
