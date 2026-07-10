---
title: Abnormally High Number of Cloud Infrastructure API Calls
slug: 2024-01-abnormal-cloud-api-calls
description: Detection of an abnormally high number of cloud infrastructure API calls, indicating potential malicious activity or misconfiguration in a cloud environment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - api-abuse
  - anomaly-detection
vendors:
  - Amazon
  - Microsoft
products:
  - Amazon S3
  - Azure Blob Storage
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/abnormally_high_number_of_cloud_infrastructure_api_calls.yml
rules:
  - title: Detect Abnormally High Number of Cloud Infrastructure API Calls
    description: Detects an abnormally high number of API calls to cloud infrastructure services, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Excessive Cloud Storage API Calls
    description: Detects excessive API calls related to cloud storage services, indicating potential data exfiltration or unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1020
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This brief addresses the detection of unusually high volumes of API calls directed at cloud infrastructure services. While the specific actor and campaign details are not available, the increase in API calls could indicate various malicious activities, including reconnaissance, privilege escalation attempts, or data exfiltration. It could also be attributed to misconfigured automation or overly aggressive legitimate processes. The focus is on establishing baseline API call volumes and identifying deviations that warrant further investigation. This is crucial for defenders to detect malicious or accidental abuse of cloud resources before significant damage can occur.

## Attack Chain

1. **Initial Access (Hypothetical):** Attacker gains initial access through compromised credentials or an exploited cloud service vulnerability (e.g., CVE-XXXX-YYYY, if applicable).
2. **Credential Harvesting/Enumeration:** The attacker attempts to enumerate cloud resources and services via API calls to identify potential targets and accessible data.
3. **Privilege Escalation:** The attacker leverages identified vulnerabilities or misconfigurations to escalate privileges within the cloud environment. This often involves excessive API calls related to IAM roles and policies.
4. **Data Access:** Once elevated privileges are achieved, the attacker makes numerous API calls to access and potentially download sensitive data stored in cloud storage services (e.g., S3 buckets, Azure Blob Storage).
5. **Lateral Movement (Hypothetical):** The attacker utilizes compromised credentials or API keys to move laterally to other cloud accounts or services.
6. **Data Exfiltration:** Large volumes of data are exfiltrated through API calls, potentially using compression or encryption to evade detection.
7. **Persistence (Hypothetical):** The attacker establishes persistent access by creating new IAM users or modifying existing roles and policies using API calls.

## Impact

Successful exploitation can lead to data breaches, service disruption, and financial losses. An abnormally high number of API calls could signify reconnaissance activities preceding a larger attack, the exfiltration of sensitive data, or the unauthorized modification of cloud resources. The number of potential victims is dependent on the scope and nature of the cloud environment being targeted, ranging from small businesses to large enterprises.

## Recommendation

*   Implement and tune the Sigma rule "Detect Abnormally High Number of Cloud Infrastructure API Calls" to identify suspicious API activity (Rule).
*   Establish baselines for normal API call volumes for different services and user accounts within your cloud environment.
*   Monitor cloud provider logs for API calls originating from unusual locations or user agents (Log Source).
*   Review and enforce the principle of least privilege for all IAM roles and users, limiting unnecessary API access (General Configuration).
