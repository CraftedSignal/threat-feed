---
title: Suspicious AWS EC2 Key Pair Creation from Non-Cloud AS
slug: 2024-01-aws-ec2-keypair-creation
description: An AWS EC2 CreateKeyPair event triggered by a new principal originating from a network autonomous system (AS) organization not associated with major cloud providers, indicating potential unauthorized access or persistence activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ec2
  - keypair
  - persistence
  - credential_access
  - lateral_movement
vendors:
  - Amazon
  - Google
  - Microsoft
products:
  - Amazon EC2
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateKeyPair.html
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1552/004/
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/004/
rules:
  - title: AWS EC2 CreateKeyPair from Non-Cloud AS Organization
    description: Detects EC2 KeyPair creation events from a source IP address whose ASN organization is not one of the big cloud providers.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - lateral_movement
      - persistence
    techniques:
      - T1021
      - T1021.004
      - T1098
      - T1552
      - T1552.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 KeyPair Import Activity
    description: Detects EC2 KeyPair import events which may indicate usage of previously created keys
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - lateral_movement
      - persistence
    techniques:
      - T1021
      - T1021.004
      - T1098
      - T1552
      - T1552.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert identifies suspicious activity related to the creation of EC2 key pairs within an AWS environment. Specifically, it focuses on instances where a new IAM principal (user) creates an EC2 key pair from a network source (IP address) whose autonomous system organization is not commonly associated with major cloud providers like Amazon, Google, or Microsoft. Adversaries often create key pairs for persistence or to enable unauthorized access to EC2 instances, potentially leading to data exfiltration or further malicious activities. The rule uses a new terms approach to baseline user activity, reducing noise from repeated actions while still flagging the initial suspicious key pair creation. This activity is flagged as suspicious due to originating from outside trusted ASNs.

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials or a misconfigured IAM role.
2.  The attacker attempts to enumerate existing EC2 instances and associated key pairs.
3.  The attacker uses the `CreateKeyPair` API call to generate a new SSH key pair within the AWS account. The request originates from a network with an autonomous system organization not attributed to common cloud providers.
4.  The attacker stores the private key material for later use in accessing EC2 instances.
5.  The attacker may then use the new key pair to launch new EC2 instances or import the key to existing instances. This can be done through `RunInstances` or `ImportKeyPair` operations.
6.  The attacker uses the new key pair to SSH into the newly created or compromised EC2 instances.
7.  Once inside the instances, the attacker performs malicious activities, such as data exfiltration, lateral movement, or installing malware.

## Impact

Successful exploitation can lead to unauthorized access to EC2 instances, potentially compromising sensitive data and disrupting services. A compromised AWS account can allow the attacker to steal data, establish persistence, and move laterally within the cloud environment. The lack of expected cloud provider ASN for the source IP of the `CreateKeyPair` event raises the risk profile.

## Recommendation

*   Deploy the Sigma rule "AWS EC2 CreateKeyPair from Non-Cloud AS Organization" to your SIEM and tune the `source.as.organization.name` exclusions based on your environment.
*   Review AWS CloudTrail logs for any `CreateKeyPair` events and correlate with other suspicious activity, as mentioned in the investigation steps in this brief.
*   Implement stricter IAM policies to limit the ability to create key pairs to only authorized users and roles.
*   Monitor for `RunInstances` or `ImportKeyPair` events using the newly created key names as identified from `aws.cloudtrail.request_parameters` / `response_elements`.
*   Enable and review AWS Config rules to detect and remediate misconfigurations related to IAM and EC2 key pair management.
