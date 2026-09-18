---
title: Detection of Anomalous AWS DynamoDB Scan Operations
slug: 2026-09-aws-dynamodb-scan-anomaly
description: This detection brief identifies potential data exfiltration or unauthorized collection by monitoring for unusual AWS DynamoDB Scan operations performed by users or roles exhibiting non-typical behavior.
date: "2026-09-18T19:31:48Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - exfiltration
  - detection
vendors:
  - Amazon
products:
  - DynamoDB
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Adversaries may use the Scan operation to collect sensitive information or exfiltrate data from DynamoDB tables.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: Adversaries may use the Scan operation to collect sensitive information or exfiltrate data from DynamoDB tables.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Adversaries may use the Scan operation to collect sensitive information or exfiltrate data from DynamoDB tables.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_dynamodb_scan_by_unusual_user.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable CloudTrail data events for all production DynamoDB tables.
      owner: IT Operations
      due: 48h
      evidence: Required for the Scan action to be visible in telemetry.
  hunt_leads:
    - lead: Identify all successful Scan operations in CloudTrail over the past 30 days.
      technique_id: T1213
      data_needed:
        - AWS CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Scan operations are high-value indicators for data collection.
  mitigation_plan:
    - priority: medium
      action: Restrict dynamodb:Scan permissions in IAM policies to only authorized service roles.
      owner: Identity Team
      addresses: T1213
      evidence: Least privilege access reduces the surface area for unauthorized collection.
---

This threat brief addresses the risk of unauthorized data collection and potential exfiltration from AWS DynamoDB tables. Adversaries who have compromised an IAM identity may attempt to use the DynamoDB `Scan` operation to dump large portions of a database, bypassing granular queries to exfiltrate entire table contents. This activity is monitored by tracking `Scan` operations within AWS CloudTrail data events. Because legitimate administrative or analytical tasks may occasionally involve scanning tables, this detection focuses on identifying "new" or anomalous behavior by specific users or roles compared to their historical activity within the environment. Detecting this at scale requires that CloudTrail data events be explicitly enabled for the target DynamoDB tables.

## Impact

Successful exploitation allows an adversary to gain unauthorized access to sensitive application data stored in DynamoDB. Depending on the scale of the tables targeted and the volume of data extracted, this can lead to significant data breaches, violation of privacy regulations, and potential loss of intellectual property. Organizations relying on DynamoDB for high-value user or business data are at highest risk if IAM credentials are misappropriated.

## Recommendation

1. Enable AWS CloudTrail data events for all sensitive DynamoDB tables to ensure that the `Scan` operation is captured in logs.
2. Implement monitoring based on the described "New Terms" logic to alert on users performing `Scan` operations they have not historically executed.
3. Review IAM policies for the identified actors to verify that the `dynamodb:Scan` permission is strictly limited to authorized identities and functional service roles.
4. Investigate alerts by correlating the `user.name` and `aws.cloudtrail.user_identity.arn` with the `source.ip` and `aws.cloudtrail.request_parameters` to differentiate between malicious data scraping and authorized analytical processes.
