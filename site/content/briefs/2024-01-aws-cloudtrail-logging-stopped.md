---
title: AWS CloudTrail Logging Stopped for Defense Evasion
slug: 2024-01-aws-cloudtrail-logging-stopped
description: Detection of AWS CloudTrail `StopLogging` events indicating potential defense evasion by adversaries attempting to operate undetected within a compromised AWS environment by halting the logging of their malicious activities.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - defense-evasion
  - cloud
vendors:
  - Amazon
  - Splunk
products:
  - CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Amazon Security Lake
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
iocs:
  - type: url
    value: https://splunkbase.splunk.com/app/1876
ioc_counts:
  url: 1
rules:
  - title: Detect AWS CloudTrail StopLogging Event
    description: Detects the StopLogging API call in AWS CloudTrail, indicating a potential attempt to disable logging and evade detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS CloudTrail StopLogging via CLI
    description: Detects the StopLogging API call in AWS CloudTrail invoked via the AWS CLI, indicating a potential attempt to disable logging and evade detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic detects `StopLogging` events within AWS CloudTrail logs, which is a critical action that adversaries may use to evade detection. By halting the logging of their malicious activities, attackers aim to operate undetected within a compromised AWS environment. This detection is achieved by monitoring for specific CloudTrail log entries that indicate the cessation of logging activities. Identifying such behavior is crucial for a Security Operations Center (SOC), as it signals an attempt to undermine the integrity of logging mechanisms, potentially allowing malicious activities to proceed without observation. The impact of this evasion tactic is significant, as it can severely hamper incident response and forensic investigations by obscuring the attacker's actions. The detection is based on Amazon Security Lake events.

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a vulnerability.
2.  The attacker enumerates existing CloudTrail configurations to identify the target log trails.
3.  The attacker attempts to disable logging by invoking the `StopLogging` API call on the CloudTrail service.
4.  The AWS CloudTrail service receives the `StopLogging` API request.
5.  If the attacker has sufficient privileges, the CloudTrail service processes the request, and logging is stopped for the specified trail.
6.  The attacker performs malicious activities within the AWS environment without those actions being logged by CloudTrail.
7.  The attacker attempts to delete or modify existing CloudTrail log files to further cover their tracks (not directly detected by this analytic, but a likely follow-on action).
8.  The attacker achieves their objective, such as data exfiltration or resource compromise, without immediate detection due to the disabled logging.

## Impact

Successful evasion of CloudTrail logging can severely impair incident response and forensic investigations. Without logs, identifying the scope and nature of the attack becomes significantly more challenging. Organizations may experience delayed breach detection, increased dwell time for attackers, and difficulty in recovering compromised resources. The impact can extend to compliance violations, as many regulatory frameworks require comprehensive audit logging. This is a high severity incident because it prevents security teams from understanding what an attacker did in the environment.

## Recommendation

*   Deploy the Sigma rule `Detect AWS CloudTrail StopLogging Event` to your SIEM and tune for your environment to detect instances where CloudTrail logging is stopped.
*   Investigate any detected `StopLogging` events (as surfaced by the Sigma rule) to determine whether they are authorized administrative actions or potentially malicious.
*   Monitor for unusual API calls and activities originating from the source IP addresses and user accounts identified in the `ASL AWS Defense Evasion Stop Logging Cloudtrail` search results.
*   Review and enforce strict IAM policies to minimize the potential for unauthorized users to disable CloudTrail logging to prevent future attempts at defense evasion.
*   Ingest CloudTrail logs from Amazon Security Lake into Splunk, ensuring you are using the latest version of Splunk Add-on for Amazon Web Services to use the `ASL AWS Defense Evasion Stop Logging Cloudtrail` search.
