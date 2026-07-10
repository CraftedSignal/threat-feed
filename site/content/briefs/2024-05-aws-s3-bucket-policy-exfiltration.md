---
title: AWS S3 Bucket Policy Modified to Share with External Account
slug: 2024-05-aws-s3-bucket-policy-exfiltration
description: An attacker modifies an Amazon S3 bucket policy to grant access to an external AWS account, potentially leading to unauthorized data access and exfiltration.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - s3
  - bucket_policy
  - exfiltration
vendors:
  - AWS
products:
  - S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.s3-backdoor-bucket-policy/
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html
rules:
  - title: AWS S3 Bucket Policy Added to Share with External Account
    description: Detects when an Amazon S3 bucket policy is modified to share access with an external AWS account, potentially for data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 GetObject from External Account
    description: Detects S3 GetObject requests originating from an external AWS account, after a bucket policy has been modified.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert focuses on the modification of Amazon S3 bucket policies to include external AWS accounts, a tactic that can be used for data exfiltration or establishing persistent cross-account access. The detection identifies `PutBucketPolicy` events where the S3 bucket's account ID differs from the account IDs referenced in the policy's `Effect=Allow` statements. This scenario could indicate a compromised user attaching a policy that grants access from an external AWS account controlled by the attacker. This allows continued access even if the initial compromised credentials are rotated. The rule is designed to trigger when the policy explicitly shares access with external accounts. It specifically excludes alerts where the account ID is part of the bucket’s name or resource ARN, as these are often legitimate naming conventions.

## Attack Chain

1.  An attacker compromises AWS credentials through methods like phishing, credential stuffing, or exploiting vulnerable EC2 instances.
2.  The attacker uses the compromised credentials to authenticate to the AWS Management Console or via the AWS CLI.
3.  The attacker identifies an S3 bucket containing sensitive data as a target for exfiltration or persistence.
4.  The attacker crafts a malicious bucket policy that grants `s3:GetObject`, `s3:ListBucket`, and potentially `s3:PutObject` permissions to an external AWS account they control.
5.  The attacker uses the `PutBucketPolicy` API call to apply the modified policy to the target S3 bucket. The cloudtrail event logs record this event with the request parameters and resources accessed.
6.  The external AWS account, now authorized by the modified bucket policy, accesses and exfiltrates the data using `GetObject` or other API calls.
7.  The attacker may attempt to conceal their activity by deleting CloudTrail logs or modifying other security configurations.
8.  The attacker maintains persistent access to the S3 bucket for continued data exfiltration or other malicious activities using the external AWS account.

## Impact

A successful attack can result in the exfiltration of sensitive data stored in the S3 bucket, leading to data breaches, financial loss, reputational damage, and regulatory fines. The number of victims would depend on the contents of the bucket and the data sensitivity. Sectors commonly targeted include finance, healthcare, and technology, where valuable or regulated data is stored in cloud environments. If successful, this allows attackers to maintain long-term unauthorized access, even after initial compromised credentials are changed.

## Recommendation

*   Deploy the Sigma rule "AWS S3 Bucket Policy Added to Share with External Account" to your SIEM to detect malicious bucket policy modifications (rule.title).
*   Review `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` from your CloudTrail logs to identify the actor making the policy change (rule.investigation_fields).
*   Monitor CloudTrail logs for `GetObject`, `ListBucket`, or `PutObject` events originating from external AWS account IDs found in the modified bucket policies (rule.investigation_fields).
*   Restrict `s3:PutBucketPolicy` permissions to a limited set of administrative roles using the principle of least privilege as part of your IAM hardening strategy.
*   Enable AWS Config rule `s3-bucket-policy-grantee-check` to monitor for unauthorized policy additions and trigger alerts.
