---
title: Detection of Unauthorized Amazon CloudWatch Log Stream Deletion
slug: 2026-08-cloudwatch-log-deletion
description: Adversaries may invoke the DeleteLogStream API to permanently destroy log data, impairing security monitoring and concealing malicious activity during post-exploitation.
date: "2026-08-24T09:49:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - impact
  - defense-evasion
vendors:
  - Amazon
products:
  - CloudWatch
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries may delete log streams to conceal malicious actions, impair monitoring pipelines, or remove artifacts generated during post-exploitation activity.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: This rule detects successful invocations of the DeleteLogStream API from CloudTrail.
    confidence_band: high
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/logs/delete-log-stream.html
  - https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteLogStream.html
rules:
  - title: Detect Unauthorized CloudWatch Log Stream Deletion
    description: Detects successful execution of the DeleteLogStream API by identities not associated with known automation tools, which may indicate malicious log suppression.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
      - T1562.008
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
    - action: Review existing CloudTrail logs for past DeleteLogStream API activity to establish a baseline
      owner: SOC
      due: 48h
      evidence: Source provides baseline guidance for identifying unauthorized log deletion.
  hunt_leads:
    - lead: Identify IAM roles that have successfully called DeleteLogStream within the last 30 days
      technique_id: T1562.008
      data_needed:
        - CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source notes that investigating the actor identity is a critical investigation step.
  mitigation_plan:
    - priority: medium_term
      action: Enforce least privilege for the logs:DeleteLogStream permission
      owner: IT Operations
      addresses: T1562.008
      evidence: Source suggests implementation of IAM least-privilege as a hardening measure.
---

Unauthorized deletion of Amazon CloudWatch log streams is a tactic used by adversaries to eliminate forensic artifacts and break security observability pipelines. By leveraging the `DeleteLogStream` API, attackers can permanently remove sequential log events associated with specific resources, such as Lambda functions, ECS tasks, or VPC Flow Logs. This technique is typically employed in post-exploitation scenarios to mask lateral movement, privilege escalation, or unauthorized access to AWS services. 

Defenders must differentiate between legitimate administrative cleanup, automated log rotation, and malicious destruction. While CI/CD pipelines and infrastructure-as-code (IaC) tools often programmatically manage logs, unexpected API calls from human-associated identities or non-standard user agents warrant immediate investigation. Failure to detect these actions may result in a complete loss of visibility into adversary activity, hindering incident response and root cause analysis.

## Attack Chain

1. Attacker gains initial access to an AWS environment via compromised IAM credentials or a vulnerable EC2 instance.
2. Attacker performs discovery to identify critical log streams that contain audit data or security telemetry.
3. Attacker evaluates permissions to determine if the compromised identity has `logs:DeleteLogStream` authority.
4. Attacker executes malicious activity (e.g., executing unauthorized code or modifying cloud configurations).
5. Attacker calls the `DeleteLogStream` API to remove logs associated with their session or malicious processes.
6. Attacker confirms the successful deletion of the log stream to ensure forensic artifacts are purged.
7. Attacker proceeds with further lateral movement or data exfiltration, knowing that detection mechanisms relying on those logs are impaired.

## Impact

Successful log deletion destroys historical record-keeping, which severely impacts incident response effectiveness. Organizations face significant operational risks, including the loss of audit trails required for compliance, inability to reconstruct the scope of a breach, and the potential for prolonged undetected dwell time. In environments where security alerting is dependent on real-time CloudWatch data, such deletions can disable security monitoring pipelines, rendering SIEM and anomaly detection solutions ineffective for the affected resources.

## Recommendation

* Deploy the provided Sigma rule to alert on non-automated `DeleteLogStream` events.
* Audit IAM policies to implement least-privilege access for `logs:DeleteLogStream`, ensuring only dedicated service roles can manage log lifecycles.
* Utilize AWS Config or Service Control Policies (SCPs) to implement guardrails against unauthorized modifications to critical log groups.
* Integrate log stream lifecycle management into CI/CD pipelines to prevent manual or unauthorized stream deletions.
* Review IAM user activity logs for identity patterns that frequently call destructive API operations.
