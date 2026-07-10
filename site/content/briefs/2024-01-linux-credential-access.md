---
title: Linux Credential Access via Sensitive File Monitoring
slug: 2024-01-linux-credential-access
description: This rule detects potential credential access attempts on Linux systems by monitoring access to sensitive files commonly containing credentials or configuration information.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential_access
  - linux
  - file_monitoring
vendors:
  - Linux
products:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/credential_access_collection_sensitive_files.toml
rules:
  - title: Detect Sensitive File Access for Credential Harvesting
    description: Detects processes accessing sensitive files commonly targeted for credential harvesting on Linux systems.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - linux
  - title: Detect Sudo Usage with Suspicious Command History Access
    description: Detects sudo commands followed by access to bash history files, potentially indicating credential theft attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule, sourced from Elastic's detection-rules repository on GitHub, focuses on identifying credential access attempts on Linux systems. The rule monitors access to a variety of sensitive files that commonly store credentials, configuration details, or other sensitive information that could be leveraged by attackers. While the specific attacker or campaign is not detailed in the provided source, the technique is commonly associated with post-exploitation activity where adversaries attempt to escalate privileges or move laterally within a compromised environment. The rule aims to provide defenders with visibility into unauthorized access to these critical files, allowing for rapid response and mitigation.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a Linux system through an exploit, vulnerability, or compromised credentials.
2.  Privilege Escalation (Optional): If the initial access is with limited privileges, the attacker may attempt to escalate privileges using kernel exploits, misconfigurations, or other techniques.
3.  Discovery: The attacker performs reconnaissance to identify sensitive files containing credentials or configuration information. This might involve using commands like `find`, `locate`, or `grep`.
4.  Credential Access: The attacker accesses sensitive files such as `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/var/log/auth.log`, configuration files in `/etc` related to specific services (e.g., `/etc/nginx/nginx.conf`, `/etc/apache2/apache2.conf`), `.bash_history`, `.ssh/id_rsa`, and similar files.
5.  Credential Harvesting: The attacker parses the accessed files for usernames, passwords, API keys, or other valuable credentials. Tools like `grep`, `awk`, or custom scripts may be used.
6.  Lateral Movement: Using the harvested credentials, the attacker attempts to move laterally to other systems within the network.
7.  Data Exfiltration (Optional): The attacker may exfiltrate the harvested credentials and other sensitive data to an external location.
8.  Persistence (Optional): The attacker may establish persistence using the compromised credentials or by modifying system configuration files.

## Impact

Successful credential access can lead to a wide range of negative consequences, including unauthorized access to sensitive data, system compromise, lateral movement within the network, and data exfiltration. Depending on the compromised system and the accessed credentials, the impact could range from minor data breaches to complete network compromise. This type of attack can affect any organization using Linux systems, with the severity depending on the sensitivity of the data stored on the compromised systems.

## Recommendation

*   Deploy the Sigma rules provided to your SIEM and tune them based on your environment to detect suspicious file access patterns.
*   Implement file integrity monitoring (FIM) on sensitive files to detect unauthorized modifications.
*   Enable and review audit logging on Linux systems to capture detailed information about file access events.
*   Regularly review and update user permissions to minimize the risk of unauthorized access.
*   Implement multi-factor authentication (MFA) to mitigate the impact of compromised credentials.
