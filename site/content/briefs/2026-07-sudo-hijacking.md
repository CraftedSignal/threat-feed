---
title: Detect Potential Sudo Binary Hijacking on Linux Systems
slug: 2026-07-sudo-hijacking
description: Attackers may hijack the default sudo binary on Linux systems, located at `/usr/bin/sudo` or `/bin/sudo`, replacing it with a malicious version to capture user passwords for credential access, elevate privileges, or establish persistence on the system every time the sudo binary is executed.
date: "2026-07-20T12:52:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - persistence
  - credential-access
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Attackers may hijack the default sudo binary and replace it with a custom binary or script that can read the user's password in clear text to escalate privileges
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Attackers may hijack the default sudo binary and replace it with a custom binary or script that can read the user's password in clear text to escalate privileges or enable persistence onto the system every time the sudo binary is executed.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1056
    technique_name: Input Capture
    evidence: Attackers may hijack the default sudo binary and replace it with a custom binary or script that can read the user's password in clear text
    confidence_band: high
references:
  - https://eapolsniper.github.io/2020/08/17/Sudo-Hijacking/
  - https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms
rules:
  - title: Detect Potential Sudo Binary Hijacking on Linux Systems
    description: Detects the creation or renaming of the /usr/bin/sudo or /bin/sudo binary, indicating a potential attempt to hijack the sudo utility. This can be used by attackers to capture user passwords, escalate privileges, or establish persistence.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
      - privilege_escalation
    techniques:
      - T1056
      - T1548
      - T1548.003
      - T1574
    data_sources:
      - file_event
      - linux
rules_count: 1
---

This brief details a threat where adversaries target Linux systems by attempting to hijack the `sudo` binary. The `sudo` utility is critical for allowing users to execute commands with elevated privileges. Attackers can replace the legitimate `/usr/bin/sudo` or `/bin/sudo` binary with a custom malicious version or script. This hijacked binary can then read a user's password in clear text upon execution, leading to credential theft, privilege escalation to root, or establishment of persistence on the system. While the exact initial access method is not specified, this technique typically occurs after an attacker has already gained initial access and some level of user-level execution. The threat detection focuses on the suspicious creation or renaming of the `sudo` binary, while carefully excluding legitimate package management operations (such as `dpkg`, `yum`, `apt`) and other system processes to minimize false positives. This type of activity is a significant concern for defenders as it grants attackers long-term, high-privilege access.

## Attack Chain

1. **Initial Access**: An attacker gains initial access to a Linux system, often through a compromised credential, exploited vulnerability, or malicious software execution, obtaining a non-root user shell.
2. **Privilege Enumeration**: The attacker enumerates system configurations and user privileges to identify potential pathways for privilege escalation.
3. **Identify Sudo Binary**: The attacker locates the standard `sudo` binary, typically at `/usr/bin/sudo` or `/bin/sudo`, which is a prime target for hijacking.
4. **Malicious Binary Creation**: The attacker crafts a custom malicious binary or script designed to masquerade as `sudo` but also log user passwords or perform other malicious actions.
5. **Sudo Binary Hijacking**: The attacker replaces the legitimate `sudo` binary with their malicious version, often using `mv` or `cp` commands with elevated permissions if already obtained, or through a race condition/vulnerability.
6. **User Execution**: A legitimate user, unaware of the compromise, attempts to run a command using `sudo`, triggering the malicious binary.
7. **Credential Capture & Privilege Escalation**: The malicious binary captures the user's password (e.g., by writing it to a hidden file) before potentially executing the original `sudo` functionality or granting itself root access.
8. **Persistence & Impact**: With root access and captured credentials, the attacker establishes persistence and proceeds with their objectives, such as data exfiltration, further compromise, or system sabotage.

## Impact

A successful sudo hijacking attack provides the adversary with critical capabilities, leading to severe consequences for an organization. The primary impact includes the compromise of user credentials, particularly passwords for accounts that utilize `sudo`, which can then be used for lateral movement within the network or access to other systems. More critically, it enables privilege escalation to the `root` user, granting the attacker complete control over the compromised Linux system. This level of access allows for arbitrary command execution, installation of rootkits or other malware, bypassing security controls, and maintaining stealthy persistence. The integrity of the system is severely degraded, and the attacker can exfiltrate sensitive data, disrupt operations, or use the system as a launchpad for further attacks.

## Recommendation

* Deploy the Sigma rule "Detect Potential Sudo Binary Hijacking on Linux Systems" to your SIEM and tune it for your environment.
* Ensure `file_event` logging for `creation` and `rename` events is enabled and collected from all Linux endpoints to activate the rules in this brief.
* Investigate all alerts generated by the Sigma rule by examining the `file.path` and `process.executable` fields to confirm legitimate package management processes.
* Review the user account associated with any detected `file_event` involving `sudo` binaries and cross-reference with typical user behavior.
* Verify the integrity of the `/usr/bin/sudo` and `/bin/sudo` binaries periodically by comparing their hashes against known good versions.
* Implement additional monitoring on critical systems to detect unexpected network connections or new user accounts, which may indicate broader malicious activity.
* Restrict write access to critical system directories like `/usr/bin` and `/bin` to only essential administrative processes and users.
