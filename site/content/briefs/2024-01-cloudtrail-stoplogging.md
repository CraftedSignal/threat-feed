---
title: AWS CloudTrail Logging Suspended via StopLogging API
slug: 2024-01-cloudtrail-stoplogging
description: An attacker may suspend AWS CloudTrail logging via the StopLogging API (StopLogging) to eliminate audit visibility and evade defenses.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloudtrail
  - aws
  - defense_evasion
vendors:
  - AWS
products:
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/stop-logging.html
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
  - https://attack.mitre.org/techniques/T1562/008/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: AWS CloudTrail StopLogging API Call
    description: Detects Cloudtrail logging suspension via StopLogging API
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudTrail Trail Deletion
    description: Detects deletion of CloudTrail trails
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudTrail Trail Update
    description: Detects updates to CloudTrail trails, potentially to change destination
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 3
---

The AWS CloudTrail service enables governance, compliance, operational auditing, and risk auditing of AWS accounts by logging API calls and related events. Attackers may attempt to disable CloudTrail logging to evade defenses and hide malicious activity. This brief addresses the detection of the `StopLogging` API call, which suspends CloudTrail logging. The successful invocation of `StopLogging` creates a gap in audit logs and may indicate malicious activity. Detecting this event is critical for maintaining visibility into an AWS environment and identifying potential security breaches. This activity is a classic defense evasion step taken before sensitive changes or data theft.

## Attack Chain

1.  The attacker compromises an AWS account or obtains valid credentials with sufficient permissions.
2.  The attacker authenticates to the AWS environment using the compromised credentials.
3.  The attacker uses the AWS CLI, SDK, or console to execute the `StopLogging` API call, specifying the target CloudTrail trail.
4.  CloudTrail stops recording events for the specified trail, creating a gap in audit logs.
5.  The attacker performs unauthorized actions within the AWS environment, such as modifying IAM policies, accessing sensitive data in S3, or launching EC2 instances.
6.  The attacker attempts to cover their tracks by deleting CloudTrail trails (`DeleteTrail`) or modifying trail configurations (`UpdateTrail`) after performing malicious actions.
7.  The attacker may resume logging (`StartLogging`) after completing their actions to avoid raising suspicion.

## Impact

A successful attack can lead to a significant loss of visibility into activities within an AWS environment. This can enable attackers to perform unauthorized actions, such as data theft, privilege escalation, or resource manipulation, without being detected. Depending on the scope of the compromised CloudTrail trail, the impact can range from affecting a single AWS account to an entire organization. The risk score is 47, and the severity is medium.

## Recommendation

*   Deploy the Sigma rule `AWS CloudTrail StopLogging API Call` to your SIEM to detect instances of CloudTrail logging being suspended (rule).
*   Investigate any detected `StopLogging` events immediately to determine the actor, scope, and potential impact of the logging suspension (rule).
*   Monitor for `UpdateTrail` and `DeleteTrail` events following a `StopLogging` event as further attempts to evade detection (Attack Chain).
*   Limit the ability to call the `cloudtrail:StopLogging` API action to break-glass roles only (Overview).
*   Alert on any future `StopLogging` calls to ensure immediate investigation (Overview).
*   Use AWS Config or Service Control Policies (SCPs) to enforce logging configurations (Overview).
