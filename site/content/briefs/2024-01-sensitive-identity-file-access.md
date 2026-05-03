---
title: Suspicious Process Accessing Sensitive Identity Files via Auditd
slug: 2024-01-sensitive-identity-file-access
description: This rule detects suspicious processes, such as copy utilities or scripting tools, accessing sensitive identity files on Linux systems, including Kubernetes tokens, cloud CLI configurations, and root SSH keys, indicating potential credential theft.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - linux
  - auditd
vendors:
  - Elastic
  - Amazon
  - Microsoft
  - Google
  - Docker
products:
  - Elastic Agent Auditd Manager
  - EKS
  - Azure
  - gcloud
  - Docker
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://attack.mitre.org/techniques/T1552/001/
  - https://attack.mitre.org/techniques/T1552/007/
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/credential_access_auditd_sensitive_cloud_and_host_identity_file_open.toml
rules:
  - title: Sensitive Identity File Accessed by Suspicious Process
    description: Detects processes commonly used for copying or scripting accessing sensitive identity files like Kubernetes tokens, cloud CLI configurations, and SSH keys.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
  - title: Sensitive AWS Credentials File Accessed
    description: Detects access to the AWS credentials file by a suspicious process.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
  - title: Suspicious Shell Command Accessing Sensitive Files
    description: Detects shell commands accessing sensitive files indicating possible credential access attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

This detection focuses on identifying unauthorized access to sensitive identity files on Linux systems. It leverages Auditd to monitor file access events and flags processes that are commonly used for copying, scripting, or staging files from temporary directories. The targeted files include Kubernetes service account tokens, kubelet configurations, cloud CLI configurations for AWS, Azure, and Google Cloud, root SSH keys, and Docker configurations. These files are critical for authentication and authorization within the system, and unauthorized access could lead to credential theft, privilege escalation, or lateral movement. This is especially important in cloud environments and containerized deployments where these files are commonly used for managing access to resources. The rule is designed to exclude user home paths to avoid false positives and focus on system-level access.

## Attack Chain

1. An attacker gains initial access to a Linux system through various means, such as exploiting a vulnerability or compromising credentials.
2. The attacker uses a utility like `cp`, `cat`, or `curl` to access sensitive files such as `/var/run/secrets/kubernetes.io/serviceaccount/token` or `/root/.ssh/id_rsa`.
3. Auditd logs the file access event, capturing details about the process, user, and file path.
4. The detection rule identifies the suspicious process based on its name, executable path (e.g., `/tmp/*`), or command-line arguments.
5. The rule checks if the accessed file is in the list of sensitive identity files.
6. If both conditions are met, the rule triggers an alert, indicating potential unauthorized access to sensitive credentials.
7. The attacker exfiltrates the stolen credentials or uses them to move laterally within the network.
8. The attacker uses the stolen credentials to access cloud resources or other sensitive systems.

## Impact

Successful exploitation can lead to the compromise of sensitive credentials, allowing attackers to gain unauthorized access to critical systems and data. This can result in data breaches, service disruptions, and financial losses. The targeted files contain credentials for Kubernetes clusters, cloud environments (AWS, Azure, Google Cloud), and SSH keys, potentially impacting a wide range of resources. The impact is particularly severe in environments where these credentials are used for managing critical infrastructure or accessing sensitive data.

## Recommendation

*   Deploy the Auditd Manager integration with the specified audit rules in the provided setup steps to monitor access to sensitive identity files on Linux systems. Ensure auditd is properly configured and running (`auditctl -l`) to generate the necessary logs.
*   Deploy the Sigma rules provided to detect suspicious processes accessing sensitive identity files and tune them for your environment by excluding legitimate processes or users as needed.
*   Investigate alerts generated by the Sigma rules, focusing on the process name, executable, parent command line, and the accessed file path to determine the legitimacy of the access.
*   Review and harden file permissions on shared credential stores to prevent unauthorized access. Rotate exposed keys and tokens and invalidate cloud sessions if a compromise is suspected, as suggested in the rule's documentation.
