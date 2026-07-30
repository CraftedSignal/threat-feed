---
title: AWS S3 Bucket ACL Modification to Public Access by New Identity
slug: 2026-07-aws-s3-public-acl
description: Detection of unauthorized S3 bucket ACL modifications to public-read or public-read-write by previously unseen identities, potentially indicating credential compromise for data exfiltration.
date: "2026-07-30T13:31:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - collection
  - s3
vendors:
  - Amazon
products:
  - AWS S3
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Monitoring for new identities performing this change helps surface freshly compromised credentials being used to stage data for exfiltration or inadvertently expose sensitive content.
    confidence_band: high
rules:
  - title: Detect AWS S3 Bucket ACL Modified to Public Access
    description: Detects PutBucketAcl API calls setting public canned ACLs by identities not previously seen performing this action.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1530
    data_sources:
      - cloud
      - aws
rules_count: 1
---

This detection monitors for the `PutBucketAcl` API action in AWS CloudTrail where the request parameters set a canned ACL of `public-read` or `public-read-write`. S3 bucket ACLs are a legacy access control mechanism that can, in certain configurations, bypass modern S3 Block Public Access (BPA) controls, inadvertently exposing sensitive object data to unauthenticated internet users. 

The use of a 'new identity' baseline (a principal not observed performing this action in the last 7 days) provides a high-signal mechanism to identify compromised credentials or unauthorized users staging data for exfiltration. While common in static website hosting, such changes are highly anomalous in production environments. Defenders should distinguish between legitimate infrastructure-as-code deployments (e.g., Terraform or CloudFormation) and manual or unauthorized modifications.

## Attack Chain

1. Attacker obtains valid AWS IAM credentials via phishing, leaked access keys, or session hijacking.
2. Attacker logs into the AWS environment or uses the AWS CLI/SDK to authenticate.
3. Attacker identifies a target S3 bucket containing sensitive data for exfiltration.
4. Attacker issues a `PutBucketAcl` API call to the target bucket.
5. The request applies a canned ACL of `public-read` or `public-read-write`.
6. The bucket contents become accessible to unauthenticated internet traffic, bypassing potential BPA restrictions.
7. Attacker performs `GetObject` or `ListObjects` from an external IP to exfiltrate the data.

## Impact

Successful exploitation leads to the public exposure of sensitive information stored within S3 buckets. Depending on the data sensitivity, this can result in significant data breaches, regulatory non-compliance, and potential intellectual property theft. The number of impacted victims depends on the scope of the exposure and the volume of data stored in the target bucket.

## Recommendation

- Deploy the Sigma rule below to monitor for `PutBucketAcl` events in your SIEM using AWS CloudTrail logs.
- Implement a baseline for principals authorized to modify bucket ACLs and tune the "new identity" logic to reduce false positives from known service accounts.
- Enable S3 Block Public Access at the account level to provide a defense-in-depth layer that overrides ACL-based public exposure.
- Investigate any hits by auditing the `aws.cloudtrail.user_identity.arn` and checking for subsequent `GetObject` or `ListObjects` calls from unknown IPs.
