---
title: Detection of Unauthorized S3 Bucket Public Access Policies
slug: 2026-09-aws-s3-public-policy
description: Adversaries may modify Amazon S3 bucket policies to include a wildcard ('*') principal with 'Allow' permissions, effectively making bucket contents publicly accessible for data exfiltration.
date: "2026-09-18T19:32:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - exfiltration
  - collection
vendors:
  - Amazon
products:
  - S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Adversaries or misconfigurations can leverage this exposure to exfiltrate data.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Publicly exposing an S3 bucket is one of the most common causes of sensitive data leaks in AWS environments.
    confidence_band: high
references:
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.s3-backdoor-bucket-policy/
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html
rules:
  - title: Detect AWS S3 Bucket Policy Added to Allow Public Access
    description: Detects PutBucketPolicy API calls that grant public access via a wildcard principal, potentially leading to unauthorized data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1530
      - T1537
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Cloud Security
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor CloudTrail logs for PutBucketPolicy wildcard events.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in the intelligence brief.
  hunt_leads:
    - lead: Identify all buckets with currently active public access policies containing wildcard principals.
      technique_id: T1530
      data_needed:
        - AWS Config or S3 bucket policy inventory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: General risk of public data exposure.
  mitigation_plan:
    - priority: immediate
      action: Enable S3 Block Public Access at the account level.
      owner: Cloud Security
      addresses: All S3 buckets
      evidence: Standard security hardening practice for AWS S3.
---

Adversaries and malicious actors exploit AWS S3 bucket policies by updating them to include a wildcard (Principal:"*") statement alongside an "Effect: Allow" directive. This configuration change grants access to all AWS identities, including unauthenticated users, thereby exposing bucket contents to the public internet. This technique is frequently used to facilitate data exfiltration or to store malicious content, leveraging open storage for credential harvesting and log access. 

Defenders must distinguish between unauthorized policy changes and legitimate configurations used for static website hosting or public datasets. This activity is often part of a broader campaign involving the reconnaissance of cloud infrastructure and the disabling of protective measures, such as S3 Block Public Access configurations. The scope of this threat encompasses any AWS account where identity and access management (IAM) roles have excessive permissions to perform the PutBucketPolicy API call.

## Attack Chain

1. Attacker performs reconnaissance to identify S3 buckets containing sensitive data.
2. Attacker assumes a compromised or over-privileged IAM role with permissions to modify bucket policies.
3. Attacker potentially disables protective account-level settings using PutPublicAccessBlock.
4. Attacker executes the PutBucketPolicy API call to set an overly permissive policy.
5. The bucket policy is updated to include a wildcard ("*") principal, granting universal read access.
6. Attacker leverages the public URL to exfiltrate data from the S3 bucket to an external location.
7. Attacker potentially uses the public bucket to stage additional malware or collect internal logs.

## Impact

Successful exploitation results in the exposure of potentially sensitive, regulated, or proprietary data stored in AWS S3 buckets. This can lead to data breaches, compliance violations, and the potential for unauthorized actors to use the bucket as infrastructure for further malicious activity, such as hosting phishing pages or staging additional attack tools.

## Recommendation

Prioritize the identification of unauthorized S3 policy modifications to prevent data exfiltration.

- Implement the provided Sigma rules to detect PutBucketPolicy events with wildcard principals in AWS CloudTrail logs.
- Audit existing bucket policies for 'Principal: "*"' and cross-reference these with authorized public-facing buckets (e.g., static sites).
- Enable AWS Config rules 's3-bucket-public-read-prohibited' and 's3-bucket-public-write-prohibited' to enforce security baselines.
- Restrict the 's3:PutBucketPolicy' permission to a strictly limited set of administrative roles to adhere to the principle of least privilege.
- Utilize Service Control Policies (SCPs) to explicitly deny the creation of bucket policies containing a wildcard principal across the entire organization.
