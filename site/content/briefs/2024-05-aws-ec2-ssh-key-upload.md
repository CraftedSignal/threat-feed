---
title: AWS EC2 Instance Connect SSH Public Key Upload
slug: 2024-05-aws-ec2-ssh-key-upload
description: This rule detects the uploading of new SSH public keys to AWS EC2 instances using the EC2 Instance Connect service, which could indicate an adversary attempting to maintain access, escalate privileges, or move laterally within the cloud environment.
date: "2024-05-03T14:57:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - ec2
  - ssh
  - lateral-movement
  - privilege-escalation
  - persistence
vendors:
  - Amazon Web Services
products:
  - EC2
  - EC2 Instance Connect
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques
  - https://medium.parttimepolymath.net/aws-ec2-instance-connect-a-very-neat-trick-4d2fc0c28010
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-instance-connect/
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ec2-privesc
  - https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.html
  - https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSerialConsoleSSHPublicKey.html
rules:
  - title: AWS EC2 Instance Connect SSH Public Key Uploaded
    description: Detects when a new SSH public key is uploaded to an AWS EC2 instance using the EC2 Instance Connect service.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - persistence
      - privilege_escalation
    techniques:
      - T1021.004
      - T1098.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Serial Console Access Enabled
    description: Detects when the ec2:EnableSerialConsoleAccess permission is used, potentially indicating an attempt to enable and exploit the serial console for privilege escalation.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert identifies when a new SSH public key is uploaded to an AWS EC2 instance using the EC2 Instance Connect service. Attackers may upload SSH public keys to maintain access, achieve persistence, or escalate privileges within the AWS environment. The detection focuses on the `SendSerialConsoleSSHPublicKey` and `SendSSHPublicKey` API actions. These API calls occur both when manually uploading keys and automatically when a user connects via the EC2 Instance Connect service through the CLI or AWS Management Console. This activity, while sometimes legitimate, represents a potential avenue for unauthorized access and requires scrutiny, especially if coupled with other suspicious actions. The rule is sourced from Elastic and was last updated on April 10, 2026.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or an exposed API key.
2. The attacker attempts to upload an SSH public key to an EC2 instance using the `SendSSHPublicKey` or `SendSerialConsoleSSHPublicKey` API calls.
3. The `ec2-instance-connect.amazonaws.com` service logs the `SendSSHPublicKey` or `SendSerialConsoleSSHPublicKey` API action in CloudTrail if successful.
4. The attacker leverages the uploaded SSH key to gain SSH access to the targeted EC2 instance.
5. Once inside the instance, the attacker performs reconnaissance, gathering information about the system and network configuration.
6. The attacker moves laterally to other EC2 instances or AWS services using the compromised instance as a pivot point.
7. If `SendSerialConsoleSSHPublicKey` was used, the attacker attempts privilege escalation via serial console access, potentially gaining root access.
8. The attacker achieves persistence by maintaining SSH access via the uploaded key, allowing continued access to the AWS environment.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, lateral movement within the AWS environment, and privilege escalation. This can result in data breaches, service disruption, and significant financial loss. The impact is amplified if the targeted EC2 instance hosts critical applications or data. The number of potential victims depends on the scope of the attacker's access and the sensitivity of the data stored within the compromised AWS environment.

## Recommendation

*   Review CloudTrail logs for events matching the `SendSSHPublicKey` or `SendSerialConsoleSSHPublicKey` API actions to identify potential unauthorized SSH key uploads to EC2 instances (log source: aws.cloudtrail).
*   Investigate the source IP addresses (`source.ip`) and user identities (`aws.cloudtrail.user_identity.arn`) associated with these events to determine the legitimacy of the actions.
*   Deploy the provided Sigma rule "AWS EC2 Instance Connect SSH Public Key Uploaded" to your SIEM and tune for your environment to detect potentially malicious SSH key uploads (rule: AWS EC2 Instance Connect SSH Public Key Uploaded).
*   Audit EC2 instance policies and permissions to ensure adherence to the principle of least privilege and restrict unauthorized SSH key uploads.
*   Monitor for the `ec2:EnableSerialConsoleAccess` permission usage in conjunction with `SendSerialConsoleSSHPublicKey` to identify potential privilege escalation attempts (log source: aws.cloudtrail).
