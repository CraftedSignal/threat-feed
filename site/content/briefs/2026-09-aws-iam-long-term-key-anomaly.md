---
title: Detection of Anomalous AWS IAM Long-Term Access Key Usage
slug: 2026-09-aws-iam-long-term-key-anomaly
description: This brief describes a detection capability for identifying potentially unauthorized programmatic access by monitoring for successful AWS IAM long-term access key usage originating from previously unseen source IP addresses.
date: "2026-09-18T19:25:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - credential-access
  - initial-access
vendors:
  - Amazon
products:
  - AWS IAM
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Long-term access keys belong to IAM users or the account root user. They are a common target after credential theft or leakage.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Identifies the first time, within the configured history window, that a long-term IAM access key ID is used successfully from a given source.ip.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_iam_long_term_access_key_first_seen_from_source_ip.toml
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy new-terms detection for AKIA key usage from new source IPs in CloudTrail logs
      owner: Detection Engineering
      due: 72h
      evidence: Elastic detection rule 9f8e3c5e-f72e-4e91-93f6-e98a4fae3e4f
  mitigation_plan:
    - priority: immediate
      action: Review and enforce IAM policies limiting long-term key usage; prioritize temporary credentials
      owner: IT Operations
      addresses: Credential theft and persistent access
      evidence: AWS Security Incident Response Guide
---

This detection focuses on identifying the first use of long-term AWS IAM access keys (prefixed with `AKIA`) from an unfamiliar source IP address, as recorded in AWS CloudTrail logs. Long-term access keys do not expire automatically and are frequently targeted by attackers following credential leakage or supply-chain compromises. By establishing a behavioral baseline of which IP addresses successfully authenticate with specific access keys over a six-month window, security operations teams can identify potentially compromised credentials being used by threat actors to maintain programmatic access to cloud environments. This detection specifically excludes temporary security credentials (`ASIA` prefix) to minimize noise and focus on persistent, high-value identity assets.

## Impact

Successful abuse of stolen long-term IAM keys allows adversaries to maintain persistent, programmatic access to sensitive cloud resources, including S3 buckets, secrets management services, and role-assumption APIs. Failure to detect such unauthorized usage can lead to significant data exfiltration, lateral movement within the cloud environment, or the deployment of additional malicious infrastructure.

## Recommendation

* Deploy the detection logic to monitor `logs-aws.cloudtrail-*` for successful API calls where `aws.cloudtrail.user_identity.access_key_id` starts with `AKIA` and the `source.ip` is new relative to a 6-month baseline.
* Enable MFA for all console-accessible IAM users and mandate the use of temporary, role-based credentials (STS) for programmatic workloads to minimize the reliance on long-term keys.
* Utilize the investigation fields identified in the rule - specifically `source.geo`, `user_agent.original`, and `aws.cloudtrail.user_identity.arn` - to triage alerts by comparing them against known corporate egress IPs and build environment segments.
* Deactivate and rotate any keys identified as used from unauthorized or suspicious locations immediately.
