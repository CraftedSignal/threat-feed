---
title: AWS Data Exfiltration via DataSync Task Creation
slug: 2024-01-03-aws-datasync-exfiltration
description: An attacker may create an AWS DataSync task to exfiltrate data from a private AWS location to a public one, leading to data compromise, detected by monitoring AWS CloudTrail logs for the `CreateTask` event from the DataSync service.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - datasync
  - data-exfiltration
  - cloudtrail
vendors:
  - AWS
products:
  - AWS DataSync
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
references:
  - https://labs.nettitude.com/blog/how-to-exfiltrate-aws-ec2-data/
  - https://www.shehackske.com/how-to/data-exfiltration-on-cloud-1606/
rules:
  - title: AWS DataSync Task Creation
    description: Detects the creation of an AWS DataSync task, which could indicate potential data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1119
    data_sources:
      - cloudtrail
      - aws
  - title: AWS DataSync Task with Unusual Destination
    description: Detects AWS DataSync tasks created with a destination ARN that deviates from expected patterns, potentially indicating data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1119
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic focuses on detecting the misuse of AWS DataSync for unauthorized data exfiltration. AWS DataSync is a data transfer service that can be used to move data between on-premises storage and AWS, or between AWS storage services. An attacker with sufficient privileges can create a DataSync task to copy data from a secured or private AWS resource to a publicly accessible location, potentially leading to significant data breaches. The detection logic centers around monitoring AWS CloudTrail logs for the `CreateTask` event associated with the DataSync service. This activity is a strong indicator of potential data exfiltration if the destination is unexpected or unauthorized. This analytic can help security teams quickly identify and respond to potential data exfiltration attempts via AWS DataSync.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account with sufficient privileges to use the DataSync service.
2. The attacker identifies a target data source within the AWS environment (e.g., an S3 bucket, an EC2 instance with valuable data).
3. The attacker creates a DataSync `sourceLocationArn` pointing to the identified data source.
4. The attacker configures a `destinationLocationArn` to point to an external or unauthorized AWS resource (e.g., an attacker-controlled S3 bucket).
5. The attacker initiates the `CreateTask` event using the AWS DataSync service, configuring the task to transfer data from the source to the destination.
6. AWS CloudTrail logs the `CreateTask` event, including details about the source and destination locations, the user who initiated the task, and other relevant metadata.
7. The DataSync task executes, transferring data from the source location to the attacker-controlled destination.

## Impact

Successful exploitation could lead to the unauthorized exfiltration of sensitive data from an AWS environment. The impact includes potential data breaches, compliance violations (e.g., GDPR, HIPAA), reputational damage, and financial losses. The severity depends on the type and volume of data exfiltrated, as well as the sensitivity of the affected resources. While specific numbers of victims or targeted sectors are not available in the original report, the general impact of data exfiltration can be considered high.

## Recommendation

*   Deploy the Sigma rule `AWS DataSync Task Creation` to your SIEM and tune for your environment to detect suspicious DataSync task creation activities.
*   Investigate any identified `CreateTask` events from the DataSync service where the `destinationLocationArn` is unexpected or unauthorized based on normal business operations (see rule above).
*   Monitor AWS CloudTrail logs for DataSync `CreateTask` events, focusing on the source and destination locations to detect unusual data transfer patterns (see log source in rule above).
*   Implement and enforce the principle of least privilege for AWS IAM roles and policies to limit who can create DataSync tasks and access sensitive data.
