---
title: AWS CloudTrail Log Updated
slug: 2026-07-aws-cloudtrail-updated
description: Adversaries can modify AWS CloudTrail configurations via the UpdateTrail API to reduce logging visibility, change log destinations, or weaken integrity, aiming to evade detection by preventing critical audit information from being collected or stored properly.
date: "2026-07-15T14:10:02Z"
lastmod: "2026-07-15T14:11:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - aws
  - log-auditing
  - impact
  - defense-evasion
vendors:
  - AWS
products:
  - AWS CloudTrail
affected_os:
  - Kali Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Trail modifications can be used by attackers to redirect logs to non-approved buckets, drop regions, or disable valuable selectors.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects updates to an existing CloudTrail trail via UpdateTrail API which may reduce visibility, change destinations, or weaken integrity (e.g., removing global events, moving the S3 destination, or disabling validation).
    confidence_band: high
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/update-trail.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/initial_access_suspicious_user_agent_detected_in_cloudtrail.toml
rules:
  - title: AWS CloudTrail Log Updated
    description: Detects updates to an existing CloudTrail trail via UpdateTrail API which may reduce visibility, change destinations, or weaken integrity (e.g., removing global events, moving the S3 destination, or disabling validation). Adversaries can modify trails to evade detection while maintaining a semblance of logging. Validate any configuration change against approved baselines.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1562
      - T1562.008
      - T1565
      - T1565.001
    data_sources:
      - aws.cloudtrail
rules_count: 1
updates:
  - at: "2026-07-15T14:11:44Z"
    level: L1
    summary: OS kali linux
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/initial_access_suspicious_user_agent_detected_in_cloudtrail.toml
---

Adversaries often seek to impair an organization's ability to monitor their activities, and modifying logging configurations is a key tactic. This threat involves the use of the AWS CloudTrail `UpdateTrail` API call by malicious actors to alter existing CloudTrail configurations. These modifications can include changing the S3 bucket where logs are stored, redirecting logs to a different CloudWatch Logs log group, modifying the KMS Key ID used for encryption, or disabling critical features like multi-region logging or the inclusion of global service events. The primary goal is to reduce visibility into their actions, weaken logging integrity, and evade detection by security monitoring systems. This technique allows attackers to maintain a facade of logging while preventing crucial audit data from being captured, making it harder for defenders to trace their activities.

## Attack Chain

[Attack Chain is omitted as the source only describes a single, specific API action for defense evasion, not a multi-step sequence from initial access to impact.]

## Impact

Successful modification of AWS CloudTrail logs can severely degrade an organization's security posture by creating blind spots in audit trails. If an attacker successfully reconfigures CloudTrail, security teams may lose critical visibility into API calls and other events within their AWS environment, especially during a period of active compromise. This lack of logging hinders incident response, forensic analysis, and compliance efforts, potentially allowing attackers to maintain persistence, exfiltrate data, or deploy further malicious payloads undetected. The integrity of past and future audit data is compromised, making it difficult to assess the full scope of a breach or to prove compliance with regulatory requirements.

## Recommendation

* Deploy the `AWS CloudTrail Log Updated` Sigma rule to detect any modifications to CloudTrail configurations.
* Investigate all alerts from the `AWS CloudTrail Log Updated` rule by examining the `aws.cloudtrail.user_identity.arn`, `user_agent.original`, and `source.ip` fields to verify if the user identity, user agent, or hostname involved in the `UpdateTrail` call is authorized to make such changes.
* Review the `aws.cloudtrail.request_parameters` for specific changes to `S3BucketName`, `CloudWatchLogsLogGroupArn`, `KmsKeyId`, `IsMultiRegionTrail`, or `IncludeGlobalServiceEvents` to understand the exact nature of the modification.
* Correlate `UpdateTrail` events with preceding `StopLogging` or subsequent `DeleteTrail` API calls to identify more severe attempts to disable logging entirely.
* Harden your AWS environment by constraining `cloudtrail:UpdateTrail` permissions to only authorized roles or users and require approval workflows for any CloudTrail configuration changes. Implement AWS Config rules to monitor for unauthorized modifications to CloudTrail trails.
