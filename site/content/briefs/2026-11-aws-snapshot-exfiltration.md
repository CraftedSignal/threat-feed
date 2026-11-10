---
brief_id: brief-2026-11-10-aws-snapshot-exfiltration
event_id: brief-2026-11-10-aws-snapshot-exfiltration
revision: 1
activity_at: "2026-11-10T02:36:54Z"
title: AWS EC2 snapshot permission modification
slug: 2026-11-aws-snapshot-exfiltration
description: Attackers may modify EC2 snapshot attributes to share them with unauthorized AWS accounts for data exfiltration.
date: "2026-11-10T02:36:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - cloud
  - aws
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
    evidence: Detects the modification of an EC2 snapshot's permissions to enable access from another account
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml
  - https://web.archive.org/web/20240314115300/https://www.justice.gov/file/1080281/download
rules:
  - title: Detect AWS Snapshot Attribute Modification
    description: Detects the modification of an EC2 snapshot attribute, which could indicate unauthorized sharing of snapshots with external accounts.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided detection rule and alert on ModifySnapshotAttribute events
      owner: Detection Engineering
      due: 48h
      evidence: Source provided SigmaHQ rule implementation
  mitigation_plan:
    - priority: medium
      action: Implement IAM Service Control Policies (SCPs) to restrict ec2:ModifySnapshotAttribute to specific approved roles
      owner: Cloud Infrastructure
      addresses: T1537
      evidence: Best practice for securing AWS snapshots
---

Unauthorized modification of EC2 snapshot permissions, specifically using the 'ModifySnapshotAttribute' API call, can allow an attacker to share sensitive data with an external AWS account. This technique is often a precursor to data exfiltration in cloud environments.

## Impact

Successful exploitation allows for the unauthorized copying of EBS volumes and the data contained within them to an adversary-controlled AWS account.

## Recommendation

Deploy the detection rule below to identify when snapshot attributes are modified. Audit IAM policies to restrict the 'ec2:ModifySnapshotAttribute' permission to only authorized identity and access management (IAM) roles and users. Regularly review snapshots shared with external accounts via the 'DescribeSnapshotAttribute' API.
