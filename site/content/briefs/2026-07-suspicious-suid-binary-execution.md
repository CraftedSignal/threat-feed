---
title: Suspicious SUID Binary Execution on Linux for Privilege Escalation
slug: 2026-07-suspicious-suid-binary-execution
description: A detection rule identifies the suspicious execution of SUID binaries on Linux systems by non-root users from unusual parent processes or locations, indicating potential privilege escalation attempts.
date: "2026-07-20T12:46:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - linux
  - suid
  - attack.t1548
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Detects execution of SUID binaries that may be used for privilege escalation under the root effective user when the real user and parent user are not root
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Detects execution of SUID binaries that may be used for privilege escalation under the root effective user when the real user and parent user are not root
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: process.name in ('sudoedit')
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_suspicious_suid_binary_execution.toml
  - https://attack.mitre.org/techniques/T1548/
rules:
  - title: Suspicious SUID Binary Execution on Linux
    description: Detects execution of SUID binaries for privilege escalation where the effective user is root, but the real user and parent user are not root. Detection is based on suspicious parent contexts like interpreters, short shell commands, or execution from user-writable paths.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
      - T1548.001
      - T1548.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This brief details a detection strategy for suspicious SUID (Set User ID) binary execution on Linux systems, a common technique leveraged for privilege escalation. Attackers often exploit misconfigurations or inherent design limitations of SUID binaries to gain root privileges from a non-root user context. The detection focuses on identifying scenarios where an SUID binary is executed by a non-root user, yet its effective user ID becomes root (0). Key indicators include executions where the parent process is also not root, originating from common interpreter processes (like Python, Perl, Node.js), user-writable directories (e.g., /tmp, /home), or short shell commands. This activity is critical for defenders to monitor as it represents a successful or attempted step towards full system compromise by gaining elevated access.

## Attack Chain

1. **Initial Access**: An attacker gains initial access to a Linux system, typically as a low-privileged user, through methods such as exploiting a vulnerable web application, phishing, or compromised credentials.
2. **Discovery**: The attacker performs reconnaissance to identify SUID binaries available on the system using commands like `find / -perm /4000 2>/dev/null` or identifying installed applications with known SUID vulnerabilities.
3. **Exploit SUID Binary**: The attacker identifies an SUID binary that can be misused for privilege escalation. This might involve invoking a specific SUID binary directly or through a script. For instance, `pkexec` or `passwd` can be called from an interpreter.
4. **Execute as Root**: The SUID binary is executed from a non-root parent process or a user-writable path. Due to its SUID bit, the effective user ID of the executed binary becomes root (UID 0), while the real user ID remains that of the attacker's low-privileged account.
5. **Achieve Privilege Escalation**: The execution provides the attacker with root privileges, potentially allowing them to spawn a root shell, modify system configurations, or create new root users.
6. **Maintain Persistence/Further Actions**: With root access, the attacker establishes persistence mechanisms (e.g., modifying `/etc/sudoers`, creating new services) and proceeds with further objectives such as data exfiltration, deploying additional malware, or lateral movement.

## Impact

Successful privilege escalation via SUID binary abuse grants an attacker root-level control over the compromised Linux system. This is a critical step in most sophisticated attacks, allowing the attacker to bypass security controls, access sensitive data, install rootkits or backdoors, modify system configurations for persistence, and pivot to other systems on the network. The integrity, confidentiality, and availability of the system and its hosted data are severely compromised. While specific victim counts are not available for this general technique, privilege escalation is a fundamental component of advanced persistent threats and ransomware campaigns affecting organizations across all sectors.

## Recommendation

* Deploy the provided Sigma rule to your SIEM system to detect suspicious SUID binary executions.
* Ensure comprehensive `process_creation` logging for Linux systems, including parent process details, command lines, and user/group IDs, to activate the rule effectively.
* Regularly audit SUID binaries on Linux systems and remove the SUID bit from any binaries not strictly requiring it or those known to be exploitable.
* Investigate alerts from the "Suspicious SUID Binary Execution" rule by inspecting `process.parent.command_line`, working directory, and preceding activities for obfuscation or one-liners as suggested in the rule's notes.
