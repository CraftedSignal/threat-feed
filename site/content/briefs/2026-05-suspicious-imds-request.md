---
title: Suspicious Instance Metadata Service (IMDS) API Request
slug: 2026-05-suspicious-imds-request
description: This rule detects suspicious network activity from tools or scripts attempting to access the cloud service provider's Instance Metadata Service (IMDS) API endpoint, potentially retrieving sensitive instance-specific information and credentials.
date: "2026-05-27T10:02:28Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - credential-access
  - discovery
  - cloud
  - imds
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
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect Suspicious IMDS API Request via Common Tools
    description: Detects suspicious processes commonly used for accessing the Instance Metadata Service (IMDS) API.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552.005
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious IMDS API Request from Unusual Locations
    description: Detects processes accessing the Instance Metadata Service (IMDS) API from unusual or temporary directories.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious IMDS API Request (Linux)
    description: Detects suspicious processes accessing the Instance Metadata Service (IMDS) API on Linux systems.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552.005
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This detection rule identifies processes making network requests to the Instance Metadata Service (IMDS) API endpoint (169.254.169.254). The IMDS API provides access to sensitive instance-specific information, including instance ID, public IP address, and temporary security credentials if roles are assumed by that instance. Attackers often exploit this service after gaining initial access to a cloud instance to escalate privileges and move laterally within the cloud environment. The rule focuses on detecting suspicious processes, scripts, or tools that are not typically associated with legitimate IMDS API requests. It covers Windows, macOS, and Linux systems.

## Attack Chain

1. Initial Access: An attacker gains initial access to a cloud instance through various means, such as exploiting a web application vulnerability or using compromised credentials.
2. Execution: The attacker executes a command interpreter or scripting engine (e.g., bash, PowerShell, python) on the compromised instance.
3. Discovery: The attacker uses the command interpreter or scripting engine to make a network request to the IMDS API endpoint (169.254.169.254) on port 80.
4. Credential Access: The IMDS API provides the attacker with instance metadata, including temporary security credentials associated with the instance's IAM role.
5. Privilege Escalation: The attacker uses the acquired credentials to escalate privileges within the cloud environment.
6. Lateral Movement: The attacker uses the escalated privileges to move laterally to other cloud resources, such as storage, secrets, or other instances.

## Impact

Successful exploitation of the IMDS API can lead to the compromise of sensitive cloud resources. Attackers can steal credentials, escalate privileges, and move laterally within the cloud environment, potentially causing significant damage, data breaches, or service disruptions. The number of victims and sectors targeted varies depending on the specific campaign.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious IMDS API Request via Common Tools" to your SIEM and tune for your environment.
*   Deploy the Sigma rule "Detect Suspicious IMDS API Request from Unusual Locations" to your SIEM and tune for your environment.
*   Block the IMDS API endpoint (169.254.169.254) at the network level for processes that do not require it, as described in the rule overview.
*   Review and harden instance IAM roles to limit the scope of credentials exposed through IMDS, as mentioned in the investigation guide.
*   Enforce IMDSv2, the more secure version of the IMDS API, as a preventative measure.
*   Monitor cloud control-plane telemetry for suspicious use of instance role credentials or managed identity tokens.
*   Investigate any alerts triggered by access to the IMDS API endpoint (169.254.169.254).
