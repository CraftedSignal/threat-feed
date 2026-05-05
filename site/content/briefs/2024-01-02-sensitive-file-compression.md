---
title: Linux Sensitive File Compression for Credential Access
slug: 2024-01-02-sensitive-file-compression
description: Attackers may use compression utilities like zip, tar, and gzip on Linux systems to collect and archive sensitive files containing credentials and system configurations for credential access and data exfiltration.
date: "2024-01-02T14:25:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - collection
  - linux
vendors:
  - Elastic
  - SentinelOne
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Auditbeat
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
references:
  - https://www.trendmicro.com/en_ca/research/20/l/teamtnt-now-deploying-ddos-capable-irc-bot-tntbotinger.html
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1552/001/
  - https://attack.mitre.org/tactics/TA0006/
  - https://attack.mitre.org/techniques/T1005/
  - https://attack.mitre.org/techniques/T1560/
  - https://attack.mitre.org/techniques/T1560/001/
  - https://attack.mitre.org/tactics/TA0009/
rules:
  - title: Sensitive Files Compression via Tar
    description: Detects the use of tar command to compress sensitive files, potentially for credential access or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - credential_access
    techniques:
      - T1552.001
      - T1560
    data_sources:
      - process_creation
      - linux
  - title: Sensitive Files Compression via Zip
    description: Detects the use of zip command to compress sensitive files, which could indicate credential access attempts or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - credential_access
    techniques:
      - T1552.001
      - T1560
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This threat brief focuses on the malicious use of compression utilities on Linux systems to collect sensitive information. Attackers leverage tools like `zip`, `tar`, `gzip`, `hdiutil`, and `7z` to archive files containing credentials (SSH keys, AWS credentials, Azure credentials, Docker configuration, Kubernetes configuration), configuration data (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `.bash_history`, `/etc/hosts`) and other sensitive system information. This behavior, often observed in post-exploitation scenarios, allows attackers to consolidate data for later exfiltration or lateral movement. The activity is detected by monitoring process executions involving compression tools and their command-line arguments targeting specific sensitive file paths. This technique has been observed with threat actors like TeamTNT who use similar methods to collect data before deploying IRC bots.

## Attack Chain

1.  The attacker gains initial access to a Linux system via an exploit or compromised credentials.
2.  The attacker uses commands like `find` or `locate` to identify sensitive files, such as SSH keys, AWS credentials, and configuration files within the file system (e.g., `/root/.ssh/id_rsa`, `/home/*/.aws/credentials`).
3.  The attacker employs a compression utility such as `tar`, `gzip`, or `zip` to archive the identified sensitive files into a single compressed file. For example, they might execute `tar -czvf sensitive_data.tar.gz /root/.ssh/id_rsa /etc/passwd`.
4.  The attacker stages the compressed archive in a publicly accessible directory or a temporary location to facilitate exfiltration.
5.  The attacker uses tools like `scp`, `rsync`, or `curl` to exfiltrate the compressed archive to an external server or cloud storage.
6.  The attacker removes the compressed archive from the compromised system to conceal their activities.
7.  The attacker uses the stolen credentials to gain unauthorized access to other systems or resources.
8.  The attacker performs lateral movement within the network, escalating privileges and compromising additional systems.

## Impact

Successful exploitation can lead to the compromise of sensitive credentials, allowing attackers to gain unauthorized access to critical systems and data. The scope of the impact varies depending on the compromised credentials and the level of access they provide. If AWS or Azure credentials are stolen, attackers can gain control over cloud infrastructure, potentially leading to data breaches, service disruptions, or financial losses. The number of victims varies depending on the targeting of the attacker.

## Recommendation

*   Deploy the Sigma rule "Sensitive Files Compression via Tar" to your SIEM to detect archiving of sensitive files (process_creation logs).
*   Enable process monitoring with command-line argument logging on Linux systems to capture the execution of compression utilities with sensitive file paths (Auditbeat, Elastic Defend).
*   Monitor network connections for unusual outbound traffic, especially connections originating from systems where sensitive file compression is detected (network_connection logs).
*   Implement file integrity monitoring (FIM) for sensitive files and directories (e.g., `/etc/passwd`, `/root/.ssh/`) to detect unauthorized modifications or access attempts.
*   Enforce strict access controls and least privilege principles to limit access to sensitive files and prevent unauthorized credential access (Linux system configuration).
