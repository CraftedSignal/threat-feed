---
title: AWS AMI Attribute Modification for Data Exfiltration
slug: 2024-01-aws-ami-exfiltration
description: An attacker modifies AWS AMI attributes, potentially sharing an AMI with another AWS account or making it publicly accessible, to exfiltrate sensitive data stored in AWS resources.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - ami
  - data-exfiltration
  - cloudtrail
vendors:
  - Amazon
products:
  - Amazon Elastic Compute Cloud (EC2)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
references:
  - https://labs.nettitude.com/blog/how-to-exfiltrate-aws-ec2-data/
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/
  - https://hackingthe.cloud/aws/enumeration/loot_public_ebs_snapshots/
rules:
  - title: Detect Publicly Shared AWS AMI
    description: Detects when an AWS AMI is made publicly accessible by modifying its launch permissions to include 'all'.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Externally Shared AWS AMI
    description: Detects when an AWS AMI is shared with another AWS account by modifying its launch permissions.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

An attacker leverages compromised AWS credentials or exploits a misconfigured IAM role to modify Amazon Machine Image (AMI) attributes. This modification can involve sharing the AMI with an external AWS account or making it publicly accessible. The primary goal is to exfiltrate sensitive data stored within the AMI, such as proprietary code, customer data, or internal configurations. This activity is particularly concerning due to the potential for unauthorized access to critical resources and subsequent data breaches. The technique abuses legitimate AWS functionality, making it harder to detect without specific monitoring in place. The sharing of AMI's is a common tactic to enable data exfiltration by threat actors.

## Attack Chain

1. **Initial Compromise:** The attacker gains access to an AWS account through compromised credentials, exploiting a vulnerability in a web application, or leveraging a misconfigured IAM role.
2. **Enumeration:** The attacker enumerates available AMIs within the AWS environment to identify those containing sensitive data.
3. **Privilege Escalation (If Needed):** If the initial access doesn't have sufficient privileges, the attacker attempts to escalate privileges to gain the ability to modify AMI attributes.
4. **AMI Attribute Modification:** The attacker uses the `ModifyImageAttribute` API call to modify the AMI's launch permissions. This involves adding external AWS accounts or setting the group to "all", making the AMI public.
5. **Data Exfiltration:** The attacker or a collaborator in the external AWS account copies the now-shared AMI to their own environment.
6. **Data Extraction:** The attacker launches an EC2 instance from the copied AMI and extracts the sensitive data stored within it.
7. **Cleanup (Optional):** The attacker may attempt to remove CloudTrail logs or other evidence of their activity to hinder detection.
8. **Lateral Movement or Further Attacks:** The attacker uses the exfiltrated data for further attacks, such as lateral movement within the organization's network or direct extortion.

## Impact

A successful AMI attribute modification and exfiltration can lead to significant data breaches, exposing sensitive customer data, proprietary code, or internal configurations. This can result in financial losses, reputational damage, legal liabilities, and regulatory fines. The scope of the impact depends on the sensitivity and volume of data stored within the compromised AMIs. This technique directly targets data confidentiality and integrity, potentially affecting thousands or millions of users if customer data is involved.

## Recommendation

*   Enable and monitor AWS CloudTrail logs for `ModifyImageAttribute` API calls (AWS CloudTrail ModifyImageAttribute Data Source).
*   Deploy the provided Sigma rule to detect suspicious AMI attribute modifications in your SIEM (Sigma Rule: "Detect Publicly Shared AWS AMI").
*   Implement strict IAM policies to limit the ability to modify AMI attributes to only authorized personnel (Reference: https://labs.nettitude.com/blog/how-to-exfiltrate-aws-ec2-data/).
*   Regularly review AMI launch permissions to identify any publicly shared or externally shared AMIs (Reference: https://hackingthe.cloud/aws/enumeration/loot_public_ebs_snapshots/).
*   Configure AWS Config rules to automatically detect and remediate publicly shared AMIs (Reference: https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/).
*   Alert on users who are modifying AMI attributes and do not typically perform that action.
