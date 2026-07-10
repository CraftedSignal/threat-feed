---
title: Potential Persistence via Linux File Modification
slug: 2024-11-linux-persistence-file-modification
description: This rule detects potential persistence attempts on Linux systems by monitoring file modifications of files commonly used for persistence, such as cron jobs, systemd services, message-of-the-day (MOTD), SSH configurations, shell configurations, runtime control, init daemon, passwd/sudoers/shadow files, Systemd udevd, and XDG/KDE autostart entries.
date: "2024-11-14T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - linux
  - file_integrity_monitoring
vendors:
  - Linux
products:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053.003
    technique_name: 'Scheduled Task/Job: Linux Cron'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543.003
    technique_name: 'Create or Modify System Process: Systemd Service'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.004
    technique_name: 'Event Triggered Execution:  Unix Shell Configuration'
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
  - https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms
  - https://www.elastic.co/security-labs/continuation-on-persistence-mechanisms
  - https://www.elastic.co/security-labs/approaching-the-summit-on-persistence
  - https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence
  - https://slayer0x.github.io/awscli/
rules:
  - title: Potential Persistence via Cron File Modification
    description: Detects modifications to cron-related files, which can be used for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.003
    data_sources:
      - file_event
      - linux
  - title: Potential Persistence via Systemd Service Modification
    description: Detects modifications to systemd service files, which can be used for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - file_event
      - linux
  - title: Potential Persistence via Shell Profile Modification
    description: Detects modifications to shell profile files, which can be used for persistence.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1546.004
    data_sources:
      - file_event
      - linux
rules_count: 3
---

This detection rule leverages File Integrity Monitoring (FIM) data to identify potential persistence mechanisms employed on Linux systems. Attackers often modify critical system files to ensure their malicious code persists across reboots or user logons. This rule focuses on detecting unauthorized modifications to files associated with cron jobs, systemd services, SSH configurations, shell profiles, and other persistence-related configurations. By monitoring these files for unexpected changes, defenders can identify potential compromises and prevent attackers from maintaining long-term access. The rule is designed to work with the Elastic FIM integration and requires proper configuration of the FIM policy to monitor the relevant file paths. It is crucial to tune the rule with appropriate exclusions for legitimate administrative activities to minimize false positives.

## Attack Chain

1. **Initial Access:** An attacker gains initial access to a Linux system, potentially through exploiting a vulnerability or using compromised credentials.
2. **Privilege Escalation:** The attacker escalates privileges to root or another highly privileged account using techniques such as exploiting kernel vulnerabilities or misconfigured SUID/SGID binaries.
3. **Cron Job Modification:** The attacker modifies cron job files (e.g., `/etc/crontab`, `/etc/cron.d/*`) to schedule malicious scripts or commands to run periodically.
4. **Systemd Service Modification:** The attacker modifies systemd service files (e.g., `/etc/systemd/system/*`) to create a new service or modify an existing one to execute malicious code upon system startup.
5. **Shell Profile Modification:** The attacker modifies shell profile files (e.g., `/etc/profile`, `~/.bashrc`) to execute malicious code when a user logs in.
6. **SSH Configuration Modification:** The attacker modifies SSH configuration files (e.g., `/etc/ssh/sshd_config`, `~/.ssh/authorized_keys`) to enable unauthorized access to the system.
7. **LD_PRELOAD Modification:** The attacker modifies `/etc/ld.so.preload` to inject malicious code into other processes.
8. **Persistence Achieved:** The attacker achieves persistence by ensuring their malicious code is executed automatically at system startup or user logon, allowing them to maintain long-term access to the compromised system.

## Impact

A successful persistence attack can allow attackers to maintain unauthorized access to a compromised Linux system indefinitely. This can lead to data theft, system disruption, or further exploitation of the network. The rule aims to detect these persistence attempts early, minimizing the potential damage. The rule can trigger on legitimate admin activity if not tuned properly, so careful whitelisting is needed.

## Recommendation

*   Enable the Elastic FIM integration and configure it to monitor the file paths specified in the rule query. Refer to the Elastic FIM documentation for detailed instructions.
*   Deploy the provided Sigma rule to your SIEM and tune it for your environment.
*   Investigate any alerts generated by the Sigma rule by reviewing the modified file and the user or process responsible for the modification.
*   Implement appropriate whitelists to exclude legitimate administrative activities from triggering the rule. Pay special attention to temporary files.
*   Ensure that access controls and permissions on critical system files are properly configured to prevent unauthorized modifications.
*   Regularly review and update the FIM policy to ensure it covers all relevant file paths.
