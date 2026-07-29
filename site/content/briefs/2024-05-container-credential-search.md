---
title: Suspicious Sensitive Key and Password Searches within Linux Containers
slug: 2024-05-container-credential-search
description: Adversaries may search for sensitive credentials, such as SSH keys and passwords, within Linux containers using utilities like grep and find, potentially leading to unauthorized access or container escape.
date: "2024-05-16T14:00:00Z"
lastmod: "2026-07-29T12:32:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - credential-access
  - linux
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
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://sysdig.com/blog/cve-2021-25741-kubelet-falco/
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1552/001/
  - https://attack.mitre.org/techniques/T1552/004/
  - https://attack.mitre.org/tactics/TA0006/
  - https://attack.mitre.org/techniques/T1005/
  - https://attack.mitre.org/tactics/TA0009/
  - https://attack.mitre.org/techniques/T1083/
  - https://attack.mitre.org/tactics/TA0007/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/credential_access_sensitive_keys_or_passwords_search_inside_a_container.toml
rules:
  - title: Suspicious Sensitive Key and Password Searches in Linux Containers
    description: Detects the use of system search utilities to find sensitive keys or passwords inside Linux containers.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1083
      - T1552
      - T1552.001
      - T1552.004
    data_sources:
      - process_creation
      - linux
  - title: Suspicious interactive shell execution
    description: Detects interactive shell usage with search utilities known to search for sensitive information
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1083
      - T1552
      - T1552.001
      - T1552.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
updates:
  - at: "2026-07-29T12:32:34Z"
    level: L1
    summary: OS linux
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/credential_access_sensitive_keys_or_passwords_search_inside_a_container.toml
---

This threat brief addresses the risk of attackers leveraging common system utilities within Linux containers to locate sensitive information. Specifically, it focuses on the use of tools like `grep`, `find`, `cat`, `sed`, and `awk` to search for private SSH keys and passwords. This activity, if successful, enables lateral movement within the container environment, escalation of privileges, or even container breakout to the underlying host. The targeted containers are running on Linux hosts, with the detection rule specifically designed for environments utilizing Elastic Defend for Containers, version 9.3.0 or later. Defenders should prioritize monitoring container processes for suspicious command-line arguments indicative of credential harvesting.

## Attack Chain

1. The attacker gains initial access to a container, potentially through exploiting a vulnerability in a running application.
2. The attacker executes a shell within the container, commonly `bash`, `sh`, or `zsh`.
3. The attacker uses utilities like `grep` or `find` to search the container's file system for files containing keywords such as "password", "id_rsa", or "BEGIN PRIVATE KEY".
4. The search commands may be executed directly, or through scripts, making identification more challenging.
5. If sensitive files are located, the attacker attempts to read their contents using `cat`, `sed`, or `awk`.
6. Once credentials are found, the attacker attempts to use them to gain access to other containers or the host system.
7. The attacker may also exfiltrate the credentials from the container for later use.
8. Successful credential access leads to lateral movement, data exfiltration, and potential compromise of the entire container environment.

## Impact

Compromised credentials within containers can lead to significant damage, including unauthorized access to sensitive data, lateral movement within the environment, and potential container breakouts. Depending on the organization, this can result in the compromise of hundreds or thousands of containers. Sectors reliant on containerized environments, like cloud providers and software development companies, are particularly at risk. If successful, attackers can exfiltrate sensitive data, disrupt services, or even gain complete control of the underlying host system.

## Recommendation

*   Deploy the "Suspicious Sensitive Key and Password Searches in Linux Containers" Sigma rule to your SIEM and tune it for your environment.
*   Enable Elastic Defend for Containers with a minimum version of 9.3.0 to collect the necessary process execution data for the Sigma rule above.
*   Review container security policies and practices to prevent recurrence, including enforcing least privilege access and using secrets management solutions to handle sensitive information securely.
*   Implement additional monitoring and alerting for similar suspicious activities across other containers and the host environment to detect and respond to potential threats promptly.
