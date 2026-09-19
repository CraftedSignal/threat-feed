---
title: Unauthenticated AWS S3 Bucket Access via Misconfigured Policies
slug: 2026-09-aws-s3-unauth-access
description: Adversaries leverage misconfigured S3 bucket policies to perform unauthenticated data collection, discovery, and manipulation using tools like the AWS CLI without authentication.
date: "2026-09-19T01:06:12Z"
lastmod: "2026-09-19T13:18:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - s3
  - collection
  - discovery
  - impact
vendors:
  - Amazon
products:
  - Amazon S3
  - S3
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Adversaries can specify --no-sign-request in the AWS CLI to retrieve objects from an S3 bucket without authentication.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1619
    technique_name: Cloud Storage Object Discovery
    evidence: Adversaries can specify --no-sign-request in the AWS CLI to retrieve objects from an S3 bucket without authentication.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries can specify --no-sign-request in the AWS CLI to retrieve objects from an S3 bucket without authentication.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Adversaries can specify --no-sign-request in the AWS CLI to retrieve objects from an S3 bucket without authentication.
    confidence_band: high
references:
  - https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/collection_s3_unauthenticated_bucket_access_by_rare_source.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Review and enable S3 Block Public Access for all buckets containing sensitive data.
      owner: Cloud Security
      due: 24h
      evidence: S3 misconfiguration leads to unauthorized data access.
  hunt_leads:
    - lead: Identify S3 API events where cloud.account.id is anonymous.
      technique_id: T1530
      data_needed:
        - CloudTrail data events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthenticated S3 API calls indicate potential bucket policy misconfiguration.
  mitigation_plan:
    - priority: immediate
      action: Enforce S3 Block Public Access.
      owner: Cloud Security
      addresses: S3 Misconfiguration
      evidence: AWS S3 Block Public Access settings prevent unintended public access.
updates:
  - at: "2026-09-19T13:18:35Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/collection_s3_unauthenticated_bucket_access_by_rare_source.toml
---

This threat involves adversaries exploiting misconfigured AWS S3 bucket policies or Access Control Lists (ACLs) that inadvertently allow public, unauthenticated access. By using the AWS CLI with the --no-sign-request parameter, unauthorized actors can interact with S3 buckets without needing valid IAM credentials. This activity exposes organizations to data exfiltration, unauthorized content modification, and potential data destruction. Defenders should monitor CloudTrail data events for S3 API calls where the account identifier is marked as anonymous, particularly from rare or previously unseen source IP addresses. The scope of this threat affects any organization with S3 buckets, especially those where public access settings are not enforced or bucket policies are overly permissive (e.g., using 'Principal: *').

## Attack Chain

1. Attacker performs reconnaissance to identify public-facing or misconfigured S3 buckets using OSINT or scanners.
2. Attacker verifies the misconfiguration by attempting an unauthenticated listing of bucket contents (ListBucket/ListObjects).
3. Attacker uses the AWS CLI with the --no-sign-request flag to interface with the S3 bucket.
4. Attacker executes Discovery commands (e.g., ListObjects) to map the bucket structure and identify high-value data.
5. Attacker executes Collection commands (e.g., GetObject) to exfiltrate files from the S3 bucket.
6. Attacker may perform Impact operations (e.g., DeleteObject or PutObject) to destroy or manipulate sensitive data.

## Impact

Successful exploitation leads to unauthorized data access, potential exfiltration of sensitive information such as PII or credentials, and malicious modification or destruction of stored objects. The severity depends on the contents of the exposed bucket, but it represents a high risk for data privacy and organizational integrity.

## Recommendation

1. Enable S3 Block Public Access at the bucket or account level to prevent unintentional public exposure.
2. Audit all S3 bucket policies and ACLs for overly permissive 'Principal: *' entries.
3. Enable CloudTrail Data Events for all sensitive S3 buckets to ensure visibility into GetObject and ListObjects actions.
4. Deploy the suggested detection logic to alert on unique source IP addresses performing anonymous S3 API calls.
5. Use AWS Access Analyzer to proactively identify buckets that allow public access.
