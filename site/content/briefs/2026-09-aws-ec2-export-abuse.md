---
title: Abuse of AWS EC2 Export APIs for Data Exfiltration
slug: 2026-09-aws-ec2-export-abuse
description: Adversaries with compromised AWS credentials can exploit EC2 export APIs to copy entire virtual machine states or images to external storage for data exfiltration.
date: "2026-09-19T01:06:35Z"
lastmod: "2026-09-19T13:24:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - exfiltration
  - collection
  - aws
vendors:
  - Amazon
products:
  - Elastic Compute Cloud (EC2)
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Adversaries can leverage these actions to copy full VM state or images out of the environment for exfiltration.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
    evidence: Adversaries can leverage these actions to copy full VM state or images out of the environment for exfiltration.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html
  - https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport_image.html
  - https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/aws-ami-store-s3-exfiltration.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_ec2_export_task.toml
rules:
  - title: Detect AWS EC2 Export Task
    description: Detects successful execution of EC2 export APIs (CreateInstanceExportTask, ExportImage, CreateStoreImageTask) which can be used to exfiltrate VM images.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the AWS EC2 Export Task detection rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation for rule deee5856-25ba-438d-ae53-09d66f41b127
  hunt_leads:
    - lead: Search for past EC2 export activities to baseline authorized migrations.
      technique_id: T1567.002
      data_needed:
        - CloudTrail API logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Investigative steps suggested by the rule source
  mitigation_plan:
    - priority: medium
      action: Review and harden IAM policies for export-related actions.
      owner: IT Operations
      addresses: T1567.002
      evidence: Official AWS guidance and rule triage advice
updates:
  - at: "2026-09-19T13:24:18Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_ec2_export_task.toml
---

Adversaries possessing sufficient IAM permissions within an AWS environment can leverage specific EC2 management APIs to exfiltrate sensitive data. By invoking the CreateInstanceExportTask, ExportImage, or CreateStoreImageTask actions, an attacker can create a copy of an EC2 instance or an Amazon Machine Image (AMI) and export it to an external destination, such as an Amazon S3 bucket. While these operations are standard for legitimate workflows like disaster recovery, cloud migration, or backup processes, they provide a powerful mechanism for unauthorized actors to bypass traditional data egress controls by extracting entire virtual machine disks or system snapshots. Once the data is moved to an S3 bucket or transferred off-account, it becomes significantly harder for organizations to monitor or prevent the exposure of sensitive workloads, including production databases and critical configuration files.

## Attack Chain

1. The attacker gains initial access to the AWS environment, often through compromised IAM credentials or a hijacked session.
2. The attacker uses reconnaissance APIs, such as DescribeInstances or DescribeImages, to identify high-value targets containing sensitive data.
3. The attacker confirms that the compromised IAM principal has the necessary permissions (e.g., ec2:CreateInstanceExportTask, ec2:ExportImage) to initiate an export.
4. The attacker executes the chosen export API call (CreateInstanceExportTask, ExportImage, or CreateStoreImageTask) targeting the identified instance or AMI.
5. The AWS EC2 service processes the request, creating a snapshot or export task and moving the data to a specified S3 bucket.
6. The attacker modifies S3 bucket policies or ACLs to allow cross-account access or public reading, if the bucket is under their control.
7. The attacker downloads the exported disk image or system state from the S3 bucket to their local infrastructure to complete the exfiltration.

## Impact

Successful exploitation allows for the full exfiltration of virtual machine disk contents, which may include databases, source code, credentials, and sensitive system logs. This can lead to significant data breaches, exposure of intellectual property, and compliance failures. The number of impacted systems is limited only by the permissions of the compromised principal and the inventory of the target AWS account.

## Recommendation

1. Deploy the provided detection rule to identify successful EC2 export tasks in CloudTrail logs.
2. Implement strict IAM policies following the principle of least privilege, specifically restricting access to ec2:CreateInstanceExportTask and ec2:ExportImage to only authorized service principals.
3. Enable AWS Config or CloudTrail alerts to monitor for large S3 bucket writes or modification of bucket policies (PutBucketPolicy) related to storage buckets used for export tasks.
4. Audit existing EC2 export workflows to establish a baseline of normal, expected behavior for DevOps and migration teams.
