---
title: Multi-Cloud CLI Token and Credential Access via Command-Line Harvesting
slug: 2024-01-multi-cloud-cli-token-harvesting
description: This rule detects command-line activity indicative of credential access across multiple cloud platforms (GCP, Azure, AWS, GitHub, DigitalOcean, Oracle, Kubernetes), looking for specific commands used to print or access tokens and credentials, flagging hosts where multiple cloud targets are accessed within a five-minute window, suggesting potential credential harvesting activity.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - cloud
  - cli
  - token-harvesting
vendors:
  - Elastic
  - Google
  - Microsoft
  - GitHub
  - DigitalOcean
  - Oracle
products:
  - gcloud
  - azd
  - gh
  - aws
  - kubectl
  - doctl
  - oci
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://attack.mitre.org/techniques/T1528/
  - https://attack.mitre.org/techniques/T1552/
rules:
  - title: Multi-Cloud CLI Token and Credential Access Commands
    description: Detects command-line activity indicative of credential access across multiple cloud platforms.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1528
      - T1552
      - T1552.001
    data_sources:
      - process_creation
      - windows
  - title: Kubectl Config View Raw Token Extraction
    description: Detects attempts to extract Kubernetes cluster credentials via kubectl config view --raw
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - process_creation
      - windows
  - title: AWS STS Get-Session-Token
    description: Detects attempts to retrieve temporary AWS credentials using aws sts get-session-token.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This threat brief focuses on detecting command-line credential harvesting across multiple cloud platforms. Attackers may attempt to steal application access tokens or extract credentials from files by executing specific commands via command-line interfaces (CLIs) for GCP, Azure, AWS, GitHub, DigitalOcean, Oracle, and Kubernetes. This activity is particularly concerning when originating from the same host within a short time frame (e.g., five minutes), potentially indicating automated credential theft. This technique can lead to unauthorized access to cloud resources, data breaches, and lateral movement within cloud environments. Defenders should monitor for suspicious command-line activity involving cloud CLIs and credential access patterns.

## Attack Chain

1. An attacker gains initial access to a system, possibly via compromised credentials or exploiting a vulnerability.
2. The attacker uses a shell (cmd.exe, PowerShell, bash, etc.) to execute cloud CLI commands.
3. The attacker executes commands to list available credentials or tokens (e.g., `aws configure list`, `az account list`, `kubectl config view`).
4. The attacker executes commands to print access tokens for various cloud providers (e.g., `gcloud auth print-access-token`, `az account get-access-token`, `gh auth token`).
5. The attacker uses credential harvesting commands across multiple cloud platforms within a short timeframe.
6. The attacker exfiltrates the harvested credentials to a remote location.
7. The attacker uses the stolen credentials to access sensitive cloud resources and data.
8. The attacker performs lateral movement within the cloud environment.

## Impact

A successful attack can lead to unauthorized access to sensitive cloud resources, data breaches, and lateral movement within cloud environments. The impact includes potential data exfiltration, service disruption, and financial loss. The number of affected victims will depend on the scope of the compromised credentials and the attacker's ability to exploit them.

## Recommendation

*   Deploy the Sigma rule "Multi-Cloud CLI Token and Credential Access Commands" to your SIEM to detect suspicious command-line activity related to cloud credential harvesting.
*   Review `Esql.process_command_line_values` in the rule output to identify the exact commands executed and determine if the activity was legitimate or malicious.
*   Correlate the detected activity with authentication, Kubernetes audit, and cloud API logs to confirm unauthorized access and misuse of printed tokens.
*   Implement monitoring and alerting for unusual CLI activity originating from user workstations or build servers, focusing on the CLIs mentioned in the Overview section.
*   Follow vendor-specific guidance to revoke compromised credentials, such as revoking tokens and rotating secrets, as outlined in the rule's "Response and remediation" section.
