---
title: Detecting Anomalous API Calls by AssumedRole Entities in AWS
slug: 2026-10-cloud-api-anomalies
description: This analytic identifies potential unauthorized access or credential misuse by detecting API calls performed by AWS 'AssumedRole' entities that deviate from historical behavioral baselines.
date: "2026-10-05T12:05:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - anomaly
  - detection
vendors:
  - Amazon
products:
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The following analytic detects cloud API calls executed by user roles that have not previously run these commands... this behavior could indicate potential malicious activity or unauthorized actions.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/cloud_api_calls_from_previously_unseen_user_roles.yml
action_plan:
  priority: enrich_before_decision
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy baseline tracking searches for AWS CloudTrail API activity
      owner: Detection Engineering
      due: 72h
      evidence: Source documentation for baseline implementation
  hunt_leads:
    - lead: Identify AssumedRole entities executing high-impact API calls for the first time
      technique_id: T1078
      data_needed:
        - AWS CloudTrail
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Analytic identifies new API call execution for AssumedRole
---

This detection focuses on identifying suspicious activity within AWS environments by monitoring API calls executed by users with the 'AssumedRole' type. Attackers often compromise temporary security credentials to move laterally or persist within a cloud environment; these activities frequently involve executing API calls that the legitimate service role has never performed before. By utilizing historical baselines of user-command associations in AWS CloudTrail, this analytic triggers alerts when a role executes a command for the first time or after a significant period of inactivity. This is critical for defenders because it surfaces potentially malicious reconnaissance, privilege escalation, or exfiltration efforts that rely on abusing existing, yet previously underutilized, IAM roles.

## Impact

Successful exploitation of compromised 'AssumedRole' identities can lead to full account takeover, unauthorized access to sensitive cloud resources, data exfiltration from S3 buckets, and the modification of security groups or IAM policies to maintain persistent backdoor access within the AWS infrastructure.

## Recommendation

* Ingest AWS CloudTrail logs into your SIEM and enable the baseline correlation searches defined in the Splunk Security Content framework ('Previously Seen Cloud API Calls Per User Role - Initial' and 'Update').
* Configure the `cloud_api_calls_from_previously_unseen_user_roles_activity_window` macro to align with your organization's risk appetite and operational cadence.
* Use the detected `user` and `command` artifacts to pivot into risk-based analysis, specifically reviewing historical risk events for the target entity to identify broader patterns of compromise.
* Baseline 'AssumedRole' activity during initial deployment windows to minimize false positives associated with standard CI/CD pipelines or automated infrastructure configuration tools.
