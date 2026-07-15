---
title: AWS EC2 AMI Shared with Another Account
slug: 2026-07-aws-ec2-ami-shared
description: Adversaries with existing AWS access may exfiltrate sensitive data by sharing Amazon Machine Images (AMIs) containing secrets, bash histories, or code artifacts with external, attacker-controlled AWS accounts, detectable via `ModifyImageAttribute` actions in AWS CloudTrail logs.
date: "2026-07-15T14:06:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - exfiltration
  - ami
vendors:
  - Amazon
products:
  - Amazon EC2
  - Amazon Machine Image
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Adversaries with access may share an AMI with an external AWS account as a means of data exfiltration.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/
iocs:
  - type: domain
    value: ec2.amazonaws.com
  - type: domain
    value: assets.marketplace.amazonaws.com
  - type: domain
    value: workspaces.amazonaws.com
  - type: domain
    value: backup.amazonaws.com
ioc_counts:
  domain: 4
rules:
  - title: AWS EC2 AMI Shared with Another Account
    description: Detects when an AWS Amazon Machine Image (AMI) is shared with an external AWS account, a common technique for data exfiltration by adversaries. This monitors ModifyImageAttribute actions in CloudTrail logs.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - aws
rules_count: 1
---

This threat brief details how adversaries can exploit Amazon Machine Image (AMI) sharing functionality within AWS to exfiltrate sensitive data. Once an attacker gains privileged access to an AWS account, they may identify valuable AMIs that could contain secrets, bash histories, code artifacts, and other confidential information. They then share these AMIs with an external AWS account under their control, effectively moving the data out of the victim's environment. This activity is primarily detected by monitoring `ModifyImageAttribute` actions in AWS CloudTrail logs, specifically when AMI launch permissions are modified to include additional user accounts. While legitimate AMI sharing is common, unauthorized sharing poses a significant data exfiltration risk. It is crucial for defenders to distinguish between legitimate and malicious sharing events, particularly by filtering out actions initiated by AWS services such as Marketplace, WorkSpaces, or Backup.

## Attack Chain

1. **Initial Access**: An adversary obtains privileged access to a victim's AWS account, often through compromised credentials or exploitation of vulnerable services.
2. **Discovery**: The attacker enumerates available Amazon Machine Images (AMIs) and identifies those that likely contain sensitive data or configurations.
3. **Privilege Escalation/Credential Access**: The adversary ensures they possess or acquire IAM permissions (e.g., `ec2:ModifyImageAttribute`) necessary to modify AMI sharing settings.
4. **AMI Sharing**: The attacker invokes the `ModifyImageAttribute` API action to grant launch permissions for the target AMI to an external AWS account under their control.
5. **Instance Launch**: From their own AWS account, the adversary launches an EC2 instance using the shared AMI.
6. **Data Extraction**: The attacker connects to the newly launched EC2 instance and extracts sensitive information (e.g., SSH keys, configuration files, source code, environment variables, database credentials) from the AMI's filesystem or memory.
7. **External Exfiltration**: The extracted sensitive data is then transferred from the attacker's AWS environment to their external storage or command and control infrastructure.

## Impact

Successful exploitation of unauthorized AMI sharing leads directly to data exfiltration, compromising sensitive information such as proprietary code, intellectual property, credentials, and customer data. If the AMIs contain critical system configurations or secrets, adversaries could leverage this information for further attacks, including lateral movement, privilege escalation, or access to other cloud resources. The number of victims and sectors targeted can vary widely depending on the attacker's objectives and the nature of the compromised organization. Organizations face significant financial, reputational, and regulatory consequences due to data breaches.

## Recommendation

* Deploy the Sigma rule "AWS EC2 AMI Shared with Another Account" to your SIEM and tune for your environment, paying close attention to the `userIdentity.invokedBy` field to filter legitimate AWS service actions.
* Review AWS CloudTrail logs for `ModifyImageAttribute` actions, specifically investigating events where `requestParameters.LaunchPermission.Add.Items` indicates an addition to AMI launch permissions.
* Validate all instances of AMI sharing with external AWS account IDs (e.g., `act-123456789012`) to ensure they are authorized and intended.
* Implement strict IAM policies to limit `ec2:ModifyImageAttribute` permissions to only authorized roles and users, following the principle of least privilege.
