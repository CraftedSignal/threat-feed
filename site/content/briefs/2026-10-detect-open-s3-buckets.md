---
title: Detection of Unauthorized Public S3 Bucket Exposure via AWS CLI
slug: 2026-10-detect-open-s3-buckets
description: This analytic identifies potential data exfiltration risks by monitoring AWS CloudTrail logs for 'PutBucketAcl' events that grant public access to S3 buckets using the AWS CLI.
date: "2026-10-08T19:05:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - data-exposure
  - aws
vendors:
  - Amazon
products:
  - S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: The following analytic detects the creation of open/public S3 buckets via the AWS CLI.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/cli/latest/reference/s3api/create-bucket.html
rules:
  - title: Detect New Open S3 Buckets over AWS CLI
    description: Detects the creation or modification of S3 bucket ACLs to allow public or authenticated user access via AWS CLI
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1530
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for public ACL modification
      owner: Detection Engineering
      due: 48h
      evidence: This detection mitigates the risk of unauthorized data exposure
  mitigation_plan:
    - priority: immediate
      action: Enable S3 Block Public Access at the account or bucket level
      owner: Cloud Infrastructure Team
      addresses: T1530
      evidence: AWS best practice to prevent accidental exposure
---

This detection focuses on identifying the creation or modification of AWS S3 bucket Access Control Lists (ACLs) that result in public exposure. By monitoring AWS CloudTrail logs for the `PutBucketAcl` event, the detection specifically flags instances where the `userAgent` indicates the use of the AWS CLI, and permissions are modified to include "AllUsers" or "AuthenticatedUsers." This behavior is often associated with either administrative oversight or malicious attempts to stage data for unauthorized exfiltration. Because public S3 buckets provide a direct vector for data breaches, this detection is critical for maintaining cloud data governance and preventing accidental or intentional exposure of sensitive assets. Security teams should use this analytic to trigger immediate investigations into the intent behind newly public buckets and ensure that only authorized services remain accessible to external entities.

## Impact

Successful exploitation of misconfigured or intentionally opened S3 buckets results in the exposure of sensitive organizational data, including PII, intellectual property, or internal configuration files. Such incidents can lead to large-scale data breaches, regulatory non-compliance, and significant reputational damage. The ability to monitor these modifications in real-time is vital for limiting the window of exposure and ensuring prompt remediation of insecure cloud storage configurations.

## Recommendation

Prioritize the implementation of this detection logic within your SIEM environment to gain visibility into cloud configuration changes.

- Integrate AWS CloudTrail logs using the Splunk AWS Add-on or App for AWS to enable the search logic provided in this brief.
- Review the results of the detection to distinguish between legitimate administrative configurations and unauthorized activity; apply filters for known-safe service accounts.
- Monitor the `bucketName` field reported by the detection to immediately audit the contents of newly exposed buckets.
- Investigate the `user` and `principalId` associated with the activity to ensure that the AWS CLI caller is authorized to modify bucket permissions.
