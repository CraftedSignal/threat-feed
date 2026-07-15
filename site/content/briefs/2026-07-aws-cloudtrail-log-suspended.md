---
title: AWS CloudTrail Log Suspended
slug: 2026-07-aws-cloudtrail-log-suspended
description: This brief describes the critical defense evasion tactic of suspending AWS CloudTrail logging via the StopLogging API, used by threat actors to eliminate audit visibility before performing sensitive operations or exfiltrating data, thereby concealing their activities and hindering incident response.
date: "2026-07-15T13:57:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - defense-evasion
  - cloud-security
vendors:
  - AWS
products:
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects Cloudtrail logging suspension via StopLogging API. Stopping CloudTrail eliminates forward audit visibility and is a classic defense evasion step before sensitive changes or data theft.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects Cloudtrail logging suspension via StopLogging API. Stopping CloudTrail eliminates forward audit visibility and is a classic defense evasion step before sensitive changes or data theft.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/stop-logging.html
rules:
  - title: AWS CloudTrail Log Suspended
    description: Detects CloudTrail logging suspension via the StopLogging API. This eliminates forward audit visibility and is a classic defense evasion step before sensitive changes or data theft.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
      - T1562.008
    data_sources:
      - service
      - aws
      - cloudtrail
rules_count: 1
---

This brief focuses on a significant defense evasion technique employed in cloud environments: the suspension of AWS CloudTrail logging. Threat actors utilize the `StopLogging` API call to halt the recording of API activity within an AWS account. This action is a critical preparatory step, executed post-compromise to eliminate forward audit visibility and obscure their tracks before performing sensitive operations such as modifying critical configurations, exfiltrating data from S3 buckets, or altering IAM policies. By temporarily blinding security monitoring tools that rely on CloudTrail logs, attackers aim to evade detection and complicate incident response efforts. While not tied to a specific campaign or threat actor, this technique is a common component of various post-compromise playbooks, highlighting its importance for defenders monitoring AWS environments.

## Attack Chain

1. **Initial Compromise**: An attacker successfully gains unauthorized access to AWS credentials, potentially through phishing, exposed access keys, or exploiting vulnerabilities in a public-facing application or service, which possess sufficient permissions to manage CloudTrail.
2. **Execution of `StopLogging` API Call**: Using the compromised credentials, the attacker invokes the `cloudtrail:StopLogging` API via the AWS Command Line Interface (CLI), AWS Software Development Kit (SDK), or directly through the AWS Management Console.
3. **Suspension of Audit Logging**: The invocation of `StopLogging` immediately ceases the recording of API calls and related events to the targeted CloudTrail, effectively creating a blind spot for security monitoring and auditing systems.
4. **Execution of Primary Malicious Objective**: With audit visibility impaired, the attacker proceeds to carry out their main objective, which may include modifying critical infrastructure configurations, exfiltrating sensitive data from storage services like S3, deleting crucial resources, or making changes to identity and access management (IAM) policies, all while minimizing their digital footprint.
5. **Obscuring Tracks**: To further evade detection or complicate forensic analysis, the attacker may subsequently attempt to resume logging using `StartLogging`, delete the CloudTrail completely (`DeleteTrail`), or modify its configuration (`UpdateTrail`) to redirect logs or reduce their granularity.

## Impact

The successful suspension of AWS CloudTrail logging has immediate and severe consequences for an organization's security posture. The primary impact is a complete loss of audit visibility into activities within the compromised AWS account for the duration of the logging suspension. This blind spot makes it exceedingly difficult to detect ongoing malicious activities, understand the scope of a breach, or conduct effective forensic investigations. Attackers can leverage this window to perform data exfiltration, modify critical infrastructure, create backdoors, or elevate privileges undetected. While specific victim counts are not tied to this general technique, any organization relying on CloudTrail for compliance, security monitoring, or operational auditing would face significant risks, including regulatory non-compliance, financial loss due to data breaches, and extended recovery times.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to detect `StopLogging` API calls in your AWS CloudTrail logs.
* Configure AWS CloudTrail to log all management events, S3 data events, and Lambda data events to ensure comprehensive coverage, leveraging the `aws.cloudtrail` log source.
* Implement AWS Identity and Access Management (IAM) policies to limit `cloudtrail:StopLogging` permissions to only essential "break-glass" roles, ensuring that the `aws.cloudtrail.user_identity.arn` field is closely monitored.
* Integrate a Cloud Security Posture Management (CSPM) solution to continuously monitor and enforce logging configurations and alert on any unauthorized changes or suspensions, which can be observed through `event.action: "StopLogging"`.
* Establish immediate alerts for `event.action: "StopLogging"` events, triggering automated playbooks for investigation and potential remediation, including reviewing `user_agent.original` and `source.ip` for suspicious activity.
