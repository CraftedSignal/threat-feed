---
title: AWS EC2 Instance Connect SSH Public Key Upload Detection
slug: 2026-07-aws-ec2-instance-connect-ssh-key-upload
description: Adversaries may upload SSH public keys to AWS EC2 instances via the EC2 Instance Connect service using the `SendSSHPublicKey` or `SendSerialConsoleSSHPublicKey` API actions, which can serve as a mechanism for initial access, persistence, or privilege escalation, particularly if the `SendSerialConsoleSSHPublicKey` action is coupled with unauthorized serial console access.
date: "2026-07-15T14:40:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - lateral-movement
  - privilege-escalation
  - persistence
vendors:
  - Amazon Web Services
products:
  - EC2 Instance Connect
  - EC2 instances
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Identifies when a new SSH public key is uploaded to an AWS EC2 instance using the EC2 Instance Connect service. This action could indicate an adversary attempting to maintain access to the instance.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may upload SSH public keys to EC2 instances to maintain access to the instance or for initial access. The rule covers cases where the `SendSerialConsoleSSHPublicKey` API action is used to upload an SSH public key to a serial connection, which can be exploited for privilege escalation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may upload SSH public keys to EC2 instances to maintain access to the instance or for initial access. This action could indicate an adversary attempting to maintain access to the instance.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques
  - https://medium.parttimepolymath.net/aws-ec2-instance-connect-a-very-neat-trick-4d2fc0c28010
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-instance-connect/
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ec2-privesc
  - https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.html
  - https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSerialConsoleSSHPublicKey.html
rules:
  - title: AWS EC2 Instance Connect SSH Public Key Uploaded
    description: Detects when a new SSH public key is uploaded to an AWS EC2 instance using the EC2 Instance Connect service, which adversaries may use for persistence or privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
      - persistence
      - privilege_escalation
    techniques:
      - T1021
      - T1021.004
      - T1098
      - T1098.004
    data_sources:
      - cloud
      - aws
rules_count: 1
---

This threat brief focuses on the detection of SSH public key uploads to AWS EC2 instances via the EC2 Instance Connect service. Adversaries can leverage the `SendSSHPublicKey` and `SendSerialConsoleSSHPublicKey` API actions to establish persistent access, facilitate lateral movement, or escalate privileges within a compromised AWS environment. While these actions are also used legitimately by administrators to connect to instances, their use by unauthorized actors indicates a significant security breach. Attackers typically exploit compromised AWS credentials to perform these actions, gaining a persistent foothold that can bypass other access controls. Detecting these API calls is crucial for identifying unauthorized access attempts and mitigating potential impact, especially when targeting critical EC2 instances or the serial console, which can offer advanced access capabilities.

## Attack Chain

1. **Compromised AWS Credentials**: An adversary obtains valid AWS credentials (e.g., access keys, temporary security credentials) through various initial access vectors such as phishing, exposed secrets, or exploiting vulnerable web applications.
2. **Target Identification**: The adversary identifies a specific EC2 instance within the compromised AWS environment for which they want to establish persistent access or escalate privileges.
3. **SSH Key Generation**: The adversary generates their own SSH key pair (a private key and a public key) for illicit access.
4. **Public Key Upload via Instance Connect**: The adversary invokes the EC2 Instance Connect service, utilizing either the `SendSSHPublicKey` or `SendSerialConsoleSSHPublicKey` API action, to upload their generated SSH public key to the targeted EC2 instance.
5. **Persistent SSH Access**: Following a successful public key upload, the adversary can now establish a direct SSH connection to the EC2 instance using their private key, thereby gaining persistent access without needing to repeatedly use the initially compromised AWS credentials.
6. **Lateral Movement and Privilege Escalation**: With persistent SSH access to the EC2 instance, the adversary can execute commands, exfiltrate data, use the instance as a pivot point to move laterally to other AWS resources, or attempt privilege escalation if the instance's attached roles have elevated permissions.

## Impact

If an adversary successfully uploads an SSH public key to an EC2 instance, the primary impact is persistent unauthorized access to that instance. This persistence allows the attacker to maintain a foothold in the environment, even if the initially compromised AWS credentials are revoked. From the compromised instance, attackers can execute arbitrary code, steal sensitive data, deploy malware, or further pivot to other services and resources within the AWS account, leading to broader data breaches, service disruptions, or resource manipulation. If the `SendSerialConsoleSSHPublicKey` action is exploited, it could enable access that bypasses typical network-based security controls, presenting a higher risk for privilege escalation and deeper compromise.

## Recommendation

* Deploy the Sigma rule "AWS EC2 Instance Connect SSH Public Key Uploaded" to your SIEM and tune for your environment to detect successful `SendSSHPublicKey` or `SendSerialConsoleSSHPublicKey` API calls.
* Ensure AWS CloudTrail logging is enabled for all AWS accounts, specifically for the `ec2-instance-connect.amazonaws.com` service provider, to generate the necessary log data for the rule.
* Investigate all alerts generated by the "AWS EC2 Instance Connect SSH Public Key Uploaded" rule by reviewing the `aws.cloudtrail.user_identity.arn`, `source.ip`, and `aws.cloudtrail.request_parameters` fields to identify the actor and context.
* Establish baselines for legitimate SSH key uploads to EC2 instances to reduce false positives and quickly identify anomalous activity.
* Regularly audit `ec2:EnableSerialConsoleAccess` permissions within your AWS environment, paying close attention to who has the authority to use the `SendSerialConsoleSSHPublicKey` API action.
