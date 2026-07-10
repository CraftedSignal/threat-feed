---
title: AWS EC2 Instance Export for Potential Exfiltration
slug: 2024-01-aws-ec2-export
description: An attacker with compromised AWS credentials or EC2 instance access can leverage EC2 export functionalities (CreateInstanceExportTask, ExportImage, or CreateStoreImageTask) to exfiltrate sensitive data by exporting EC2 instances or their images to external storage.
date: "2024-01-02T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ec2
  - exfiltration
  - cloudtrail
vendors:
  - AWS
products:
  - EC2
  - S3
  - IAM
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
references:
  - https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html
  - https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport_image.html
  - https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/aws-ami-store-s3-exfiltration.html,
rules:
  - title: AWS EC2 Export Task
    description: Detects successful EC2 instance export tasks via CreateInstanceExportTask, ExportImage, or CreateStoreImageTask APIs which can indicate potential data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Bucket ACL Modification After EC2 Export
    description: Detects modifications to S3 bucket ACLs following an EC2 export task, which could indicate an attempt to grant unauthorized access to the exported data.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The AWS EC2 service provides features to export EC2 instances and their images, commonly used for legitimate purposes like VM migration, backup, or cloning. However, malicious actors can abuse these features (specifically the `CreateInstanceExportTask`, `ExportImage`, and `CreateStoreImageTask` APIs) to exfiltrate data from compromised AWS environments. This involves exporting a running or stopped EC2 instance (or its AMI/image) to external storage, such as S3, or other image formats. Once exported, the data can be transferred off-account, leading to potential data breaches. This activity may go unnoticed if proper monitoring isn't in place, as the actions themselves are standard AWS functionalities. Defenders need to monitor these API calls closely, especially when performed by unfamiliar users or from unexpected locations, to differentiate between legitimate administrative tasks and malicious exfiltration attempts.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account or EC2 instance through methods like credential theft, privilege escalation, or exploiting misconfigurations.
2. The attacker uses the `CreateInstanceExportTask` API to initiate the export of a running or stopped EC2 instance to an S3 bucket. This requires specifying the instance ID, target environment, and S3 bucket details in the `request_parameters`.
3. Alternatively, the attacker uses the `ExportImage` API to export an AMI (Amazon Machine Image) to an S3 bucket. This involves defining parameters like the image ID, disk image format, and S3 bucket location.
4. Another alternative is to use the `CreateStoreImageTask` to create a store-backed image.
5. The attacker configures the S3 bucket ACLs (Access Control Lists) or bucket policies using `PutBucketAcl` or `PutBucketPolicy` to allow cross-account access or public access to the exported data.
6. The attacker downloads the exported instance data or image from the S3 bucket to a local machine or another cloud environment. This may involve large data transfers that could be identified as anomalies.
7. The attacker may copy or share the exported image by using the `CopyImage`, `ModifyImageAttribute`, or `ShareImage` API calls.
8. The attacker exfiltrates the sensitive data contained within the exported instance or image, achieving their objective of data theft.

## Impact

Successful exploitation can lead to the exfiltration of sensitive data stored on EC2 instances, including databases, application code, and proprietary information. The number of affected instances and the volume of data exfiltrated will vary depending on the scope of the attacker's access and the resources targeted. Industries handling sensitive data, such as healthcare, finance, and government, are at higher risk. The consequences range from regulatory fines and reputational damage to intellectual property theft and competitive disadvantage.

## Recommendation

*   Deploy the Sigma rule "AWS EC2 Export Task" to your SIEM and tune for your environment to detect potential EC2 instance export activity (rule).
*   Investigate alerts triggered by the Sigma rule "AWS EC2 Export Task" by examining `aws.cloudtrail.user_identity.arn`, `user_agent.original`, `source.ip`, `aws.cloudtrail.request_parameters`, and `aws.cloudtrail.response_elements` (rule).
*   Monitor for unusual S3 bucket activity, such as cross-account ACL changes or large data downloads, related to the S3 bucket specified in `aws.cloudtrail.request_parameters` of EC2 export events (Attack Chain).
*   Restrict IAM permissions to limit which users can perform `CreateInstanceExportTask`, `ExportImage`, and `CreateStoreImageTask` actions to minimize the attack surface (Overview).
*   Implement monitoring for follow-on tasks such as `CopyImage`, `ModifyImageAttribute`, or `ShareImage` events related to exported images (Attack Chain).
