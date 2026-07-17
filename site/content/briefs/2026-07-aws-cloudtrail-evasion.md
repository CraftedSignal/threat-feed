---
title: AWS CloudTrail Management Events Disabled via PutEventSelectors
slug: 2026-07-aws-cloudtrail-evasion
description: A malicious actor uses the AWS CloudTrail `PutEventSelectors` API call to explicitly disable logging of management API calls for a trail by setting `includeManagementEvents` to `false`, effectively blinding defenders to subsequent sensitive activities while the trail appears active.
date: "2026-07-17T08:13:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - defense-evasion
vendors:
  - Amazon Web Services
products:
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects CloudTrail PutEventSelectors calls where the legacy event selectors explicitly set includeManagementEvents to false, disabling capture of all management API calls for that trail. This technique is documented in Stratus Red Team as aws.defense-evasion.cloudtrail-event-selectors.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-event-selectors/
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: AWS CloudTrail Management Events Disabled via PutEventSelectors
    description: Detects CloudTrail PutEventSelectors calls where the legacy event selectors explicitly set includeManagementEvents to false, disabling capture of all management API calls for that trail, serving as a stealthy defense evasion technique.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.008
    data_sources:
      - aws.cloudtrail
rules_count: 1
---

Malicious actors may exploit the AWS CloudTrail `PutEventSelectors` API call to disable the logging of management events within a CloudTrail trail, a stealthy defense evasion technique. By setting the `includeManagementEvents` parameter to `false`, an attacker can selectively blind defenders to critical activities such as IAM changes, credential operations, or resource abuse, while the CloudTrail service itself continues to appear active in the AWS console. This method provides a more subtle evasion compared to directly stopping logging or deleting a trail, which leave more overt traces. Documented as a known pre-exfiltration step in Stratus Red Team under `aws.defense-evasion.cloudtrail-event-selectors`, this technique can silently persist for extended periods, making timely detection crucial. Defenders need to implement specific monitoring to identify these surgical modifications and prevent attackers from operating undetected within AWS environments.

## Attack Chain

1. Attacker gains initial access to an AWS account, typically through compromised credentials or exploitation of a vulnerable service.
2. Attacker performs reconnaissance using API calls such as `GetTrailStatus`, `GetEventSelectors`, or `DescribeTrails` to identify active CloudTrail configurations and their logging scope.
3. Attacker selects a specific CloudTrail trail whose logging needs to be impaired for subsequent malicious activities.
4. Attacker crafts a `PutEventSelectors` API call, specifically manipulating the request parameters to modify the identified CloudTrail trail's event selectors.
5. Within the `PutEventSelectors` call, the attacker explicitly sets `includeManagementEvents` to `false` for the targeted trail, disabling the capture of all management API calls.
6. The `PutEventSelectors` call is executed successfully, altering the CloudTrail configuration to stop logging crucial management events, while allowing data events to continue logging (if configured).
7. The CloudTrail continues to display as "Active" in the AWS console, creating a false sense of security for defenders as critical audit logs are silently omitted.
8. Attacker proceeds with high-impact malicious actions, such as modifying IAM roles, creating new user credentials, or exfiltrating data, knowing these activities will now go unlogged by the tampered CloudTrail.

## Impact

Successful execution of this technique severely degrades an organization's visibility into their AWS environment, enabling attackers to conduct sensitive operations such as IAM privilege escalation, creation of backdoors, or data exfiltration without generating corresponding CloudTrail management event logs. This blinds security teams to critical adversarial actions, significantly delaying incident detection and response. The impact is magnified if the affected trail is a multi-region or organization-wide trail, leading to a broad visibility gap across the AWS estate. The lack of audit trails makes post-incident forensics and attribution significantly more challenging, allowing attackers to persist longer and inflict more damage.

## Recommendation

* Deploy the Sigma rule "AWS CloudTrail Management Events Disabled via PutEventSelectors" to your SIEM and tune for your environment to detect attempts to disable management event logging.
* Regularly review `aws.cloudtrail.user_identity.arn` associated with `PutEventSelectors` actions. High-confidence adversarial activity is indicated by AKIA* keys or root identity changes outside of IaC deployment pipelines.
* Investigate the `aws.cloudtrail.request_parameters` for `PutEventSelectors` events to confirm if `includeManagementEvents: false` is present and identify any additional narrowing of logging by `ReadWriteType` or `DataResources`.
* Correlate all API activity from the time a `PutEventSelectors` event (where `includeManagementEvents` was set to `false`) occurred until detection. Utilize alternative log sources such as CloudWatch or other regional trails to identify high-impact API calls, particularly IAM changes, credential operations, or S3/KMS data access, that might have gone unlogged during this gap window.
* Restrict `cloudtrail:PutEventSelectors` permissions to only break-glass roles and enforce this through AWS Service Control Policies (SCPs) to prevent unauthorized modifications.
