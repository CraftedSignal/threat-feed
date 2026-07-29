---
title: Cloud Credential Search in Containers Detected
slug: 2026-07-cloud-cred-search-container
description: An attacker using system search utilities like `grep` or `find` within a containerized environment to locate cloud credentials (AWS, Azure, GCP) indicates an attempt to gain unauthorized access to sensitive cloud resources or perform a container breakout to compromise the underlying cloud infrastructure.
date: "2026-07-29T12:30:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - credential-access
  - discovery
  - cloud
  - linux
vendors:
  - Amazon
  - Microsoft
  - Google
products:
  - Amazon Web Services (AWS)
  - Microsoft Azure
  - Google Cloud Platform (GCP)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This rule detects the use of system search utilities like grep and find to search for AWS credentials inside a container.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This rule detects the use of system search utilities like grep and find to search for AWS credentials inside a container.
    confidence_band: high
references:
  - https://sysdig.com/blog/threat-detection-aws-cloud-containers/
rules:
  - title: Cloud Credential Search Detected via Defend for Containers
    description: Detects the use of system search utilities like grep or find to search for AWS, Azure, or GCP credentials inside a container. This indicates an attacker attempting to access sensitive cloud resources or facilitate container breakout.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1083
      - T1552
      - T1552.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat brief details the detection of malicious activity within containerized environments where an attacker actively searches for cloud credentials. Threat actors, upon gaining initial access to a container, leverage common Linux system utilities such as `grep`, `find`, `cat`, `sed`, or `awk` to scan for patterns indicative of AWS, Azure, or Google Cloud Platform credentials. This activity often occurs via shell processes like `bash` or `sh` executing these search commands. The objective is to discover sensitive information, such as `aws_access_key_id`, `AZURE_CLIENT_SECRET`, or `private_key` from service accounts, which can then be used to escalate privileges, move laterally within the cloud environment, or execute a container breakout to compromise the underlying host or other cloud services. Early detection of such credential discovery attempts is critical to prevent broader cloud infrastructure compromise.

## Attack Chain

1. **Initial Container Compromise**: An attacker gains initial access to a running container, typically through exploiting a vulnerable application, misconfiguration, or exposed service.
2. **Establish Container Access**: The attacker establishes persistent access or obtains a shell within the compromised container environment.
3. **Discovery of System Utilities**: The attacker identifies and confirms the availability of common Linux system search utilities (`grep`, `find`, `cat`, `sed`, `awk`) within the container's file system.
4. **Credential Search Execution**: The attacker executes these utilities, either directly or via a shell process (`bash`, `sh`, `zsh`), specifying arguments designed to locate files or environment variables containing cloud credential patterns (e.g., `aws_access_key_id`, `AZURE_CLIENT_SECRET`, `application_default_credentials.json`).
5. **Credential Acquisition**: The search commands successfully identify and extract sensitive cloud credentials from configuration files, metadata services, or environment variables present in the container.
6. **Cloud Privilege Escalation/Lateral Movement**: Using the acquired credentials, the attacker attempts to escalate privileges within the associated cloud environment or move laterally to access other cloud resources, services, or connected containers.
7. **Container Breakout (Optional)**: In some advanced scenarios, the attacker may leverage the discovered credentials or further container vulnerabilities to perform a container breakout, gaining access to the underlying host operating system or other parts of the cloud infrastructure.
8. **Impact and Persistence**: The attacker achieves their final objective, which may include data exfiltration, resource manipulation, service disruption, or establishing persistence in the cloud environment.

## Impact

Successful credential search and acquisition within a container can lead to severe consequences, including unauthorized access to sensitive data, compromise of cloud resources, and financial loss due to misuse of cloud accounts. Attackers can leverage these credentials to escalate privileges, move laterally across cloud services, deploy additional malicious infrastructure, or achieve a container breakout, impacting the underlying host and potentially the entire cloud tenant. The compromise of a single container can therefore serve as a gateway to broader cloud environment devastation.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to detect attempts to search for cloud credentials within containers.
* Ensure `process_creation` logs are collected from your container environments with `product: linux` to activate the rule above.
* Review access controls for all cloud resources to ensure least privilege is applied, minimizing the impact of compromised credentials.
* Regularly scan container images for embedded static credentials or misconfigurations that could lead to initial access or credential exposure.
* Implement runtime defense for containers to monitor and block suspicious process execution as identified by the Sigma rule.
* Rotate cloud credentials frequently and use temporary credentials (e.g., IAM roles, managed identities) where possible to reduce the window of exposure for compromised long-lived credentials.
