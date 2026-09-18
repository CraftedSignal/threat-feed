---
title: AWS EC2 EBS Snapshot Exfiltration via ModifySnapshotAttribute
slug: 2026-09-aws-ebs-snapshot-sharing
description: Adversaries may exploit the ModifySnapshotAttribute API to share Amazon EBS snapshots with external accounts or the public, facilitating data exfiltration and unauthorized access to sensitive volume data.
date: "2026-09-18T19:31:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - exfiltration
  - aws
  - monitoring
vendors:
  - Amazon
products:
  - Amazon Web Services
  - Elastic Block Store
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Adversaries may exploit ModifySnapshotAttribute to share snapshots with external accounts or the public, allowing them to copy and access data in an environment they control.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html
  - https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security Team
  immediate_actions:
    - action: Enable monitoring for the ModifySnapshotAttribute API call in AWS CloudTrail for all regions.
      owner: Cloud Security Team
      due: 24h
      evidence: Source provides the EQL query identifying this specific event.
  mitigation_plan:
    - priority: immediate
      action: Enforce a Service Control Policy (SCP) to deny public snapshot sharing.
      owner: Cloud Security Team
      addresses: Publicly accessible EBS snapshots
      evidence: AWS best practice mentioned in the source
---

Attackers target Amazon Web Services (AWS) environments by exploiting the `ModifySnapshotAttribute` API to change the permissions of Amazon Elastic Block Store (EBS) snapshots. By adding external AWS account IDs or setting the snapshot attribute to `group=all` (making the volume public), adversaries can copy and mount sensitive data volumes within their own attacker-controlled AWS environments. This technique is often a precursor to broader data exfiltration or persistence operations, as it allows attackers to bypass account-level isolation and staging of stolen data. Since snapshots often contain critical system data or database backups, unauthorized access represents a significant risk to organizational confidentiality and regulatory compliance. Defenders should monitor CloudTrail logs for successful modifications to snapshot permissions that do not align with authorized internal replication workflows or backup automation.

## Impact

Successful exploitation allows for the unauthorized extraction of data stored within EBS volumes, which may include database contents, configuration files, and sensitive application data. Once a snapshot is shared, the data can be fully replicated to an adversary's account, resulting in a complete breach of confidentiality. Publicly exposed snapshots (`group=all`) are susceptible to automated discovery by third parties, exponentially increasing the risk of data compromise.

## Recommendation

- Implement monitoring for `ModifySnapshotAttribute` API calls in CloudTrail to identify when EBS snapshots are shared with non-authorized AWS accounts or made public.
- Apply Service Control Policies (SCPs) organization-wide to explicitly prohibit the public sharing of EBS snapshots.
- Use AWS Config rules like `ebs-snapshot-public-restorable-check` to automatically detect and remediate publicly accessible snapshots.
- Restrict the `ec2:ModifySnapshotAttribute` IAM permission to only a limited set of administrative roles and enforce the use of Multi-Factor Authentication (MFA).
- Conduct regular audits of EBS snapshot permissions to identify and remove unauthorized access entries.
