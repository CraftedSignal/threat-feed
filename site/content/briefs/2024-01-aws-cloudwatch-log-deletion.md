---
title: AWS CloudWatch Log Group Deletion for Defense Evasion
slug: 2024-01-aws-cloudwatch-log-deletion
description: Attackers may delete CloudWatch log groups to evade detection and disrupt logging capabilities, hindering incident response efforts, by deleting CloudWatch log groups via the `DeleteLogGroup` API call.
date: "2024-01-03T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudwatch
  - defense-evasion
vendors:
  - Amazon
products:
  - CloudWatch
  - Amazon Security Lake
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
  - https://splunkbase.splunk.com/app/1876
rules:
  - title: Detect AWS CloudWatch Log Group Deletion
    description: Detects the deletion of CloudWatch log groups in AWS CloudTrail logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: ASL AWS Defense Evasion Delete CloudWatch Log Group - OCSF
    description: Detects the deletion of CloudWatch log groups in AWS Security Lake logs parsed in the OCSF format.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws_asl
rules_count: 2
---

The deletion of CloudWatch log groups within Amazon Web Services (AWS) represents a significant defense evasion technique. By removing these log groups, attackers aim to eliminate traces of their malicious activity, making it difficult for security teams to detect and respond to incidents effectively. The activity is identified through `DeleteLogGroup` events in CloudTrail logs, particularly when these logs are ingested via Amazon Security Lake in the OCSF format. This tactic allows attackers to cover their tracks, potentially leading to undetected data breaches or further malicious actions within the compromised AWS environment. Defenders should be vigilant for such actions, as they can severely impede incident investigation and remediation efforts. The deletion could be initiated by a compromised account or a malicious insider.

## Attack Chain

1.  Attacker gains unauthorized access to an AWS account with sufficient privileges.
2.  Attacker enumerates existing CloudWatch log groups to identify those containing sensitive or incriminating logs.
3.  Attacker uses the AWS CLI, SDK, or Management Console to issue a `DeleteLogGroup` API call, targeting specific log groups.
4.  CloudTrail logs the `DeleteLogGroup` event, capturing details such as the actor's user ID, source IP address, and the target log group name.
5.  The targeted CloudWatch log group is permanently deleted, erasing all logs it contained.
6.  Attacker repeats this process for other relevant log groups to further obscure their activities.
7.  The absence of these logs hinders security teams' ability to reconstruct the attack timeline and identify the full scope of the compromise.
8.  Attacker continues to conduct malicious operations within the AWS environment, knowing their actions are less likely to be detected.

## Impact

Successful deletion of CloudWatch log groups can severely impair an organization's ability to detect and respond to security incidents within their AWS environment. This action can lead to prolonged periods of undetected malicious activity, potentially resulting in data breaches, financial losses, and reputational damage. The lack of logs can make it nearly impossible to conduct thorough investigations, leaving organizations vulnerable to repeat attacks. While specific victim counts are unavailable, any organization leveraging AWS CloudWatch is potentially at risk.

## Recommendation

*   Deploy the Sigma rule `Detect AWS CloudWatch Log Group Deletion` to your SIEM and tune for your environment to identify potential malicious deletions of CloudWatch log groups.
*   Enable Amazon Security Lake and ingest CloudTrail logs in OCSF format to ensure comprehensive logging and visibility (see the `data_source` field).
*   Investigate any `DeleteLogGroup` events, especially those originating from unusual source IP addresses or user accounts (see the `search` field).
*   Monitor the `actor.user.uid` field for any unexpected or unauthorized deletions of CloudWatch log groups.
*   Implement multi-factor authentication (MFA) for all AWS accounts to reduce the risk of unauthorized access.
*   Review and enforce the principle of least privilege for IAM roles to limit the potential impact of compromised accounts.
