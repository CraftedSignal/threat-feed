---
title: AWS Credential Access via GetPasswordData API Calls
slug: 2024-01-aws-credential-access
description: Detection of anomalous GetPasswordData API calls in AWS CloudTrail logs, indicating potential attempts to retrieve encrypted administrator passwords for Windows instances, leading to unauthorized access.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - credential-access
  - cloudtrail
vendors:
  - Amazon
products:
  - Amazon EC2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://attack.mitre.org/techniques/T1552/
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-get-password-data/
rules:
  - title: Detect AWS GetPasswordData API Calls by User
    description: Detects AWS GetPasswordData API calls, potentially indicating credential access attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Multiple AWS GetPasswordData API Calls from Single IP
    description: Detects multiple AWS GetPasswordData API calls from a single source IP address within a short time frame, which could indicate an attacker attempting to retrieve multiple passwords.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic identifies suspicious GetPasswordData API calls within an AWS environment by analyzing CloudTrail logs ingested into Amazon Security Lake. The GetPasswordData API is used to retrieve the encrypted administrator password for Windows instances, and anomalous use of this API can signal malicious activity. The detection focuses on identifying unusual patterns, such as a single user accessing the passwords for multiple distinct EC2 instances, which deviates from typical administrative activities. The timeframe for this analytic starts from 2026-04-15. This activity is significant because successful retrieval of these passwords can grant an attacker administrative control over the target instances, enabling lateral movement, data exfiltration, or other malicious objectives. The detection leverages Amazon Security Lake as the data source, specifically CloudTrail logs, making it essential for organizations utilizing AWS to monitor for potential credential access attempts.

## Attack Chain

1.  Initial Access: An attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a misconfiguration.
2.  Privilege Escalation (if needed): The attacker may attempt to escalate privileges within the AWS account to gain the necessary permissions to call the `GetPasswordData` API.
3.  Discovery: The attacker enumerates available EC2 instances within the AWS environment to identify potential targets.
4.  Credential Access: The attacker makes `GetPasswordData` API calls to retrieve encrypted administrator passwords for the targeted Windows instances. This step is directly detected by the provided analytic.
5.  Decryption: The attacker decrypts the retrieved password data, potentially using tools and techniques available on the compromised host or through external resources.
6.  Lateral Movement: Using the decrypted administrator credentials, the attacker attempts to log into the targeted Windows instances via RDP or other remote access protocols.
7.  Persistence/Privilege Escalation (on the instance): Once inside the Windows instance, the attacker may establish persistence mechanisms (e.g., creating new accounts, installing backdoors) and further escalate privileges to gain full control of the system.
8.  Impact: The attacker uses the compromised Windows instances to achieve their objectives, such as data exfiltration, deploying ransomware, or disrupting services.

## Impact

Compromise via GetPasswordData calls can lead to full control over affected AWS EC2 instances. While the exact number of potential victims or targeted sectors is not specified in the source, the impact of such an attack can be severe, especially if critical systems are compromised. The successful retrieval and decryption of administrator passwords allows attackers to perform lateral movement, steal sensitive data, disrupt business operations, or deploy ransomware, resulting in significant financial and reputational damage.

## Recommendation

*   Deploy the provided analytic in your Splunk environment, ensuring that you are ingesting CloudTrail logs from Amazon Security Lake via the Splunk Add-on for AWS.
*   Investigate any alerts generated by the `ASL AWS Credential Access GetPasswordData` analytic, prioritizing instances where a single user is accessing passwords for multiple distinct EC2 instances.
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with administrative privileges, to mitigate the risk of compromised credentials.
*   Review and restrict IAM policies to limit the ability of users and roles to call the `GetPasswordData` API, adhering to the principle of least privilege.
*   Monitor CloudTrail logs for other anomalous API calls and activities that may indicate attacker reconnaissance or privilege escalation attempts.
*   Implement detections for successful RDP logins following `GetPasswordData` calls.
