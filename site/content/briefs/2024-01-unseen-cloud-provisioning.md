---
title: Cloud Provisioning Activity From Previously Unseen IP Address
slug: 2024-01-unseen-cloud-provisioning
description: This analytic detects cloud provisioning activities originating from previously unseen IP addresses by leveraging cloud infrastructure logs to identify events where resources are created or started, and cross-references these with a baseline of known IP addresses.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - cloudtrail
  - anomaly-detection
vendors:
  - AWS
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/cloud_provisioning_activity_from_previously_unseen_ip_address.yml
rules:
  - title: Detect Cloud Provisioning from New IP Address
    description: Detects cloud resource creation events from previously unseen IP addresses based on AWS CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudTrail - Unusual CreateUser Activity
    description: Detects the CreateUser API call in AWS CloudTrail logs, potentially indicating suspicious user creation activity.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection focuses on identifying cloud provisioning activities originating from previously unseen IP addresses. It leverages cloud infrastructure logs, specifically AWS CloudTrail, to monitor the creation or starting of cloud resources. By comparing the source IP addresses of these events against a baseline of known and trusted IPs, the analytic flags any activity originating from a previously unobserved source. This is particularly important as it can indicate unauthorized access, compromised credentials, or malicious actors attempting to deploy resources within the cloud environment. The activity is significant, as an attacker could gain unauthorized control over cloud resources, potentially leading to data breaches, service disruptions, or increased operational costs. The Splunk analytic uses data model Change and requires the `previously_seen_cloud_provisioning_activity_sources` lookup to be populated via the provided baseline searches.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to a cloud environment, potentially through compromised credentials or exploiting a vulnerability.
2.  **Privilege Escalation:** The attacker attempts to elevate their privileges within the cloud environment to gain broader control over resources.
3.  **Cloud Resource Provisioning:** The attacker uses their access to provision new cloud resources, such as virtual machines or storage buckets, from a previously unseen IP address. This provisioning activity is logged in AWS CloudTrail.
4.  **Evasion:** The attacker may attempt to evade detection by using techniques such as proxying their traffic through multiple IP addresses or leveraging compromised hosts.
5.  **Lateral Movement:** With newly provisioned resources, the attacker pivots laterally within the cloud environment to access sensitive data or systems.
6.  **Data Exfiltration / Service Disruption:** The attacker exfiltrates sensitive data from the compromised resources or disrupts critical services.

## Impact

Successful exploitation can lead to unauthorized access to cloud resources, potentially resulting in data breaches, service disruptions, or increased operational costs. The number of victims can vary depending on the scope of the attacker's access and the sensitivity of the compromised data. Sectors targeted could include any organization utilizing cloud infrastructure, with a higher risk for those handling sensitive data or providing critical services. The impact includes financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Ensure AWS CloudTrail logs are being ingested into your SIEM to provide the necessary data source for the detection.
*   Implement and maintain the `previously_seen_cloud_provisioning_activity_sources` lookup using the provided baseline searches, as mentioned in the "how_to_implement" section to establish a baseline of known IP addresses.
*   Deploy the Sigma rule provided below to detect cloud provisioning activity originating from previously unseen IP addresses.
*   Customize the `cloud_provisioning_activity_from_previously_unseen_ip_address_filter` macro, as mentioned in the "how_to_implement" section, to provide additional filtering for this search, reducing potential false positives.
*   Review and tune the risk scoring associated with the RBA (Risk Based Alerting) message to align with your organization's risk tolerance and incident response procedures.
