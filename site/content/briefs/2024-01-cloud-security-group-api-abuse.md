---
title: Abnormal Cloud Security Group API Call Activity
slug: 2024-01-cloud-security-group-api-abuse
description: Detection of an abnormally high number of cloud security group API calls which can indicate malicious activity such as reconnaissance, privilege escalation, or lateral movement within a cloud environment.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - security-group
  - api-abuse
vendors:
  - Amazon
  - Microsoft
  - Google
products:
  - Amazon Web Services
  - Microsoft Azure
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Standard Permission Groups Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/abnormally_high_number_of_cloud_security_group_api_calls.yml
rules:
  - title: Cloud Security Group API Call Volume Anomaly
    description: Detects an abnormally high number of API calls related to cloud security groups within a defined time period, indicating potential reconnaissance or malicious modification attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.002
    data_sources:
      - cloudtrail
      - aws
  - title: Suspicious Security Group Deletion Activity
    description: Detects the deletion of a security group followed by the creation of a new security group with similar attributes shortly after, potentially indicating an attempt to evade detection or bypass security controls.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on detecting anomalous activity within cloud environments, specifically related to an abnormally high number of API calls targeting security groups. While no specific actor is named, this behavior is often associated with threat actors attempting to gain unauthorized access, enumerate resources, or modify security configurations for malicious purposes. The activity is detected through analysis of cloud provider logs, looking for significant deviations from baseline API call patterns related to security groups. The scope of targeting is broad, as any organization utilizing cloud infrastructure and security groups is potentially vulnerable. This detection is crucial because unauthorized modifications to security groups can lead to significant data breaches, service disruptions, and privilege escalation scenarios.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to a cloud account through compromised credentials or exploiting a misconfigured service.
2.  **Privilege Escalation:** The attacker attempts to escalate privileges within the compromised account to gain broader access to cloud resources.
3.  **Reconnaissance:** The attacker begins enumerating cloud resources, including security groups, to identify potential targets and vulnerabilities. This stage involves an increased volume of API calls.
4.  **Security Group Enumeration:** The attacker uses cloud APIs to list existing security groups, their configurations, and associated resources. This is done to map out the network architecture and identify potential weaknesses.
5.  **Security Group Modification:** The attacker attempts to modify security group rules to allow unauthorized access to resources or to create backdoors for persistent access. This could involve opening ports or changing IP address restrictions.
6.  **Lateral Movement:** The attacker leverages the modified security groups to move laterally within the cloud environment, accessing previously restricted resources.
7.  **Data Exfiltration/Resource Abuse:** Once inside, the attacker may exfiltrate sensitive data or abuse cloud resources for malicious purposes, such as cryptocurrency mining or launching denial-of-service attacks.
8.  **Persistence:** The attacker establishes persistent access by creating new accounts or modifying existing ones, ensuring continued access even if the initial vulnerability is patched.

## Impact

Compromise of cloud security groups can lead to significant damage. Successful attacks can result in unauthorized access to sensitive data, potential data breaches, and disruption of critical services. The number of victims can range from a single organization to multiple tenants in a shared cloud environment. Sectors at risk include any organization utilizing cloud services, particularly those handling sensitive data such as healthcare, finance, and government.

## Recommendation

*   Deploy the Sigma rule "Cloud Security Group API Call Volume Anomaly" to your SIEM and tune the threshold based on your environment's baseline activity.
*   Enable and monitor cloud provider audit logs (e.g., AWS CloudTrail, Azure Activity Log, Google Cloud Audit Logs) to provide the data source for the Sigma rules.
*   Implement multi-factor authentication (MFA) for all cloud accounts to mitigate the risk of credential compromise.
