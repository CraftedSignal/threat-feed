---
title: Persistnux - Linux Persistence Detection Tool
slug: 2026-03-persistnux-tool
description: Persistnux is a bash-based tool designed to identify known Linux persistence mechanisms used by attackers to maintain access to compromised systems, generating detailed reports for DFIR analysis.
date: "2026-03-17T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - persistence
  - linux
  - dfir
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rvnvmc/persistnux_linux_persistence_tool_hunter/
  - https://github.com/go-LANz/Persistnux
rules:
  - title: Detect Init Script Modification for Persistence
    description: Detects modifications to init scripts, which can be used for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.002
    data_sources:
      - file_event
      - linux
  - title: Detect Cron Job Modification for Persistence
    description: Detects modifications to cron job files, often used for scheduling malicious tasks.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.003
    data_sources:
      - file_event
      - linux
  - title: Detect Systemd Service Modification for Persistence
    description: Detects modifications to systemd service files, which can be used for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.004
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Persistnux is a bash-based tool designed to aid security analysts and incident responders in identifying Linux persistence mechanisms employed by attackers. Developed by 0xblake, this tool streamlines the process of detecting various persistence techniques on compromised Linux systems. Persistnux performs comprehensive checks across the system, generating detailed reports in both CSV and JSONL formats for further analysis. Its key feature is its dependency-free operation, relying solely on built-in Linux tools, making it easily deployable on live systems. The tool focuses on detecting known methods used to maintain access, offering a valuable resource for defenders. It uses indicators and confidence scoring to highlight suspicious activity.

## Attack Chain

1.  **Initial Compromise:** An attacker gains initial access to a Linux system through methods such as exploiting vulnerabilities or using stolen credentials.
2.  **Privilege Escalation:** Once inside, the attacker attempts to escalate privileges to gain root access using exploits or misconfigurations.
3.  **Persistence Establishment:** The attacker employs various Linux persistence mechanisms to ensure continued access to the compromised system. These techniques include manipulating init scripts, cron jobs, and systemd services.
4.  **Init Script Modification:** The attacker modifies init scripts located in `/etc/init.d/` or `/etc/rc.d/` to execute malicious code during system startup.
5.  **Cron Job Manipulation:** The attacker schedules malicious tasks using cron jobs by adding entries to `/etc/crontab` or user-specific crontab files.
6.  **Systemd Service Modification:** The attacker creates or modifies systemd service files in `/etc/systemd/system/` to execute malicious code as a service.
7.  **Reverse Shell Installation:** The attacker installs a reverse shell to maintain persistent access by connecting back to an attacker-controlled server. This may involve techniques like download-execute or obfuscation.
8.  **Data Exfiltration/Malicious Activity:** With persistent access established, the attacker proceeds to exfiltrate sensitive data, deploy ransomware, or perform other malicious activities.

## Impact

Successful exploitation and persistence within a Linux environment can allow attackers to maintain long-term access, leading to data theft, system disruption, or the deployment of ransomware. The impact can range from data breaches and financial losses to reputational damage and operational downtime. The scope of impact depends on the level of access gained and the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule for detecting init script modifications to identify potential persistence attempts (reference: Sigma rule for init script modification).
*   Deploy the Sigma rule for detecting cron job modifications to identify potential persistence attempts (reference: Sigma rule for cron job modification).
*   Regularly audit systemd service configurations for unauthorized modifications using the Sigma rule (reference: Sigma rule for systemd service modification).
*   Use Persistnux or similar tools to regularly scan systems for known persistence mechanisms and review the generated reports (reference: Persistnux tool).
