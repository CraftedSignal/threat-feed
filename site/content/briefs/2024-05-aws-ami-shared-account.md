---
title: AWS EC2 AMI Shared with Another Account for Potential Exfiltration
slug: 2024-05-aws-ami-shared-account
description: An AWS Amazon Machine Image (AMI) being shared with another AWS account could indicate data exfiltration, as AMIs may contain sensitive data, and unauthorized sharing can lead to exposure.
date: "2024-05-03T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ami
  - exfiltration
vendors:
  - Amazon
products:
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/
rules:
  - title: AWS EC2 AMI Shared with Another Account
    description: Detects when an EC2 AMI is shared with another AWS account, potentially indicating exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 AMI Shared Publicly
    description: Detects when an EC2 AMI is made publicly accessible via ModifyImageAttribute, which can lead to unintended data exposure.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert detects when an Amazon Machine Image (AMI) is shared with another AWS account. While AMI sharing is a legitimate AWS feature, it can be abused by adversaries to exfiltrate sensitive data. AMIs often contain secrets, bash histories, code artifacts, and other sensitive data. An attacker with sufficient privileges can share an AMI with an external account under their control, effectively copying the data out of the targeted AWS environment. This rule helps identify potentially malicious AMI sharing activity. Note that AWS Marketplace subscriptions and other AWS services like workspaces.amazonaws.com and backup.amazonaws.com will legitimately invoke AMI sharing. Review such service-invoked events to confirm they match legitimate and intended sharing configurations.

## Attack Chain

1. An attacker gains initial access to an AWS account with sufficient privileges to modify AMI attributes. This could be through compromised credentials, an insider threat, or exploiting a misconfigured IAM role.
2. The attacker identifies a target AMI containing sensitive data within the AWS environment.
3. The attacker uses the `ModifyImageAttribute` API call to add a new user ID to the AMI's launch permissions, specifically the AWS account ID of an account controlled by the attacker. The `aws.cloudtrail.request_parameters` field will contain the `add` parameter with the target account.
4. The AWS EC2 service processes the `ModifyImageAttribute` request, granting the specified account access to the AMI.
5. The attacker, logged into the external AWS account, verifies they can now access the shared AMI.
6. The attacker copies the AMI to their own AWS account.
7. The attacker launches an EC2 instance from the copied AMI in their own account.
8. The attacker accesses and exfiltrates the sensitive data contained within the AMI, achieving their objective of data theft.

## Impact

Successful exfiltration of an AMI can lead to the compromise of sensitive data, including credentials, code, and configuration information. This could result in unauthorized access to other systems, data breaches, and reputational damage. The number of victims depends on the scope of data contained within the AMI. Targeted sectors could vary depending on the compromised account's role.

## Recommendation

*   Deploy the "AWS EC2 AMI Shared with Another Account" Sigma rule to your SIEM and tune for your environment (rule).
*   Investigate any detected AMI sharing events, focusing on the `aws.cloudtrail.request_parameters` and `aws.response.response_elements` fields in CloudTrail logs to identify the AMI ID and the user ID of the account with which the AMI was shared (content).
*   Review and, if necessary, revoke unauthorized shared permissions from the AMI immediately (content).
*   Implement monitoring to track changes to shared AMIs and alert on unauthorized access patterns (content).
*   Refer to the Amazon EC2 User Guide on AMIs and Sharing AMIs for more information on managing and sharing AMIs (references).
