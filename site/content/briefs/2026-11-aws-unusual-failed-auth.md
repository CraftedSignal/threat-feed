---
brief_id: brief-2026-11-28-aws-unusual-failed-auth
event_id: brief-2026-11-28-aws-unusual-failed-auth
revision: 1
activity_at: "2026-11-28T20:50:02Z"
title: 'AWS CloudTrail: Detecting password spraying via console authentication failures'
slug: 2026-11-aws-unusual-failed-auth
description: This analytic identifies potential password spraying activity targeting AWS Console logins by monitoring for a single source IP address exhibiting a statistically unusual volume of failed authentication attempts against multiple user accounts.
date: "2026-11-28T20:50:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic sourced from verified Splunk ESCU repository.
tags:
  - cloud
  - threat-detection
  - aws
  - credential-access
vendors:
  - Amazon
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.003
    technique_name: Password Spraying
    evidence: The following analytic identifies a single source IP failing to authenticate into the AWS Console with multiple valid users... this behavior is significant as it may indicate a Password Spraying attack.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.004
    technique_name: Credential Stuffing
    evidence: References include whiteoaksecurity.com/blog/goawsconsolespray-password-spraying-tool/ and documentation on protecting against credential stuffing on AWS.
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586.003
    technique_name: Cloud Accounts
    evidence: This activity is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges.
    confidence_band: med
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_unusual_number_of_failed_authentications_from_ip.yml
  - https://attack.mitre.org/techniques/T1110/003/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Implement the Splunk detection rule to identify anomalous failed authentication clusters.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided in Splunk security_content repository.
  hunt_leads:
    - lead: Identify source IPs attempting console logins across an unusually high number of unique usernames within a 10-minute window.
      technique_id: T1110.003
      data_needed:
        - AWS CloudTrail ConsoleLogin events
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: The analytic identifies a single source IP failing to authenticate into the AWS Console with multiple valid users.
---

## Overview

The Splunk ES Content Update analytic (v16) detects password spraying against the AWS Console by using CloudTrail logs to identify anomalies. The detection logic calculates the standard deviation of failed authentication attempts per source IP address over a 10-minute window, triggering an alert when the count exceeds a 3-sigma threshold (defined as greater than 10 attempts and exceeding the calculated upper bound).

## Impact

Confirmed malicious activity of this type indicates an adversary attempting to gain unauthorized access to an AWS environment. Successful exploitation can lead to account takeover, privilege escalation, and subsequent data exposure or infrastructure manipulation.

## Recommendation

- Deploy the Splunk ES analytic provided in the source to detect anomalies in ConsoleLogin failures.
- Configure the detection bucket span and upper bound threshold to align with the baseline noise levels of your specific AWS environment.
- Review identified source IPs for suspicious patterns across multiple accounts.
- Ensure the Splunk Add-on for AWS is correctly configured to ingest CloudTrail logs.
