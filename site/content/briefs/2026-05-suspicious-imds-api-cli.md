---
title: Suspicious Instance Metadata Service (IMDS) API Command Line Execution
slug: 2026-05-suspicious-imds-api-cli
description: The rule identifies command-line executions that attempt to access cloud service provider's Instance Metadata Service (IMDS) API endpoints, potentially retrieving sensitive instance information and temporary security credentials, ultimately leading to credential access and privilege escalation within the cloud environment.
date: "2026-05-27T10:02:11Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - credential-access
  - cloud
  - imds
vendors:
  - Microsoft
  - CrowdStrike
  - SentinelOne
  - Elastic
products:
  - Microsoft Defender XDR
  - Elastic Endgame
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Crowdstrike
affected_os:
  - Linux
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://hackingthe.cloud/aws/general-knowledge/intro_metadata_service/
  - https://www.wiz.io/blog/imds-anomaly-hunting-zero-day
rules:
  - title: Detect Suspicious IMDS API Access via Common Tools
    description: Detects suspicious command-line tools accessing the Instance Metadata Service (IMDS) API endpoint, indicating potential credential access attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious IMDS API Access via Shell Scripts
    description: Detects suspicious shell scripts or interpreters accessing the Instance Metadata Service (IMDS) API endpoint, indicating potential credential access attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies command-line activity that attempts to query a cloud instance's metadata service (IMDS) API endpoint. Attackers commonly exploit IMDS to retrieve sensitive instance-specific information, including instance IDs, public IP addresses, and temporary security credentials associated with assumed roles. The rule focuses on command-line tools and scripts like `curl`, `wget`, `powershell.exe`, and others, running on Linux, macOS, and Windows systems. This behavior allows attackers to gain unauthorized access to cloud resources by leveraging stolen credentials without needing passwords. The rule aims to detect this reconnaissance and credential access technique early in the attack chain.

## Attack Chain

1. An attacker gains initial access to a cloud virtual machine (VM) through methods such as exploiting a web application vulnerability or using compromised credentials.
2. Upon gaining code execution, the attacker uses a command-line tool such as `curl` or `wget` to query the local instance metadata service (IMDS) endpoint.
3. The attacker crafts a request to retrieve IAM role credentials by accessing the IMDS endpoint at `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
4. If the instance has an IAM role assigned, the IMDS API returns temporary security credentials, including an access key ID, secret access key, and session token.
5. Alternatively, the attacker may target Azure managed identities by querying `/metadata/identity/oauth2/token*resource=*`.
6. The attacker exports the retrieved credentials, writing them to disk or setting them as environment variables.
7. The attacker uses the stolen credentials to interact with cloud resources, such as accessing storage buckets, secrets management services, or IAM APIs.
8. The attacker escalates privileges and moves laterally within the cloud environment using the compromised credentials.

## Impact

Successful exploitation allows attackers to obtain sensitive cloud credentials without requiring passwords. This can lead to unauthorized access to critical cloud resources, data breaches, and privilege escalation within the victim's cloud environment. The impact may include unauthorized data access, exfiltration of sensitive information, and potentially full compromise of the cloud infrastructure. The risk score is rated at 47, emphasizing the severity of potential credential compromise.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious IMDS API Access via Common Tools" to your SIEM to identify suspicious command-line access attempts to the IMDS endpoint.
*   Enable Sysmon process creation logging to capture command-line activity on Windows systems for the Sigma rule (see logsource in rules).
*   Implement network segmentation to limit which users, services, or containers can reach the metadata endpoint as mentioned in the response and remediation steps.
*   Enforce the use of IMDSv2 (instance metadata service version 2) to mitigate the risks associated with IMDSv1, per the hardening recommendations in the analysis section.
*   Review and minimize the permissions granted to IAM roles associated with cloud instances to adhere to the principle of least privilege.
*   Monitor cloud control plane telemetry for suspicious use of instance role credentials or managed identity tokens against sensitive APIs.
