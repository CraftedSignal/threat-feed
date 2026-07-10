---
title: AWS S3 Bucket Enumeration and Brute Force Attempts
slug: 2024-05-aws-s3-bucket-enumeration
description: A high number of failed S3 operations (AccessDenied errors) against a single bucket from a single source address within a short timeframe can indicate attempts to enumerate bucket objects, brute-force object keys, or inflate AWS billing.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - s3
  - enumeration
  - brute_force
  - impact
  - discovery
  - collection
vendors:
  - Amazon
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1657
    technique_name: Financial Theft
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1619
    technique_name: Cloud Storage Object Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
references:
  - https://medium.com/@maciej.pocwierz/how-an-empty-s3-bucket-can-make-your-aws-bill-explode-934a383cb8b1
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ErrorCodeBilling.html
  - https://attack.mitre.org/techniques/T1657/
  - https://attack.mitre.org/techniques/T1580/
  - https://attack.mitre.org/techniques/T1619/
  - https://attack.mitre.org/techniques/T1530/
rules:
  - title: Detect High Volume of AWS S3 AccessDenied Errors
    description: Detects a high volume of AWS S3 AccessDenied errors from a single source IP address to a single bucket, indicating potential enumeration or brute-force attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - impact
    techniques:
      - T1580
    data_sources:
      - webserver
      - linux
  - title: Detect AWS S3 AccessDenied Errors from External Sources
    description: Detects AWS S3 AccessDenied errors from source IP addresses that are not in the internal network ranges.
    platform: sigma
    severity: low
    tactics:
      - discovery
      - impact
    techniques:
      - T1580
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This rule detects potential AWS S3 bucket enumeration, object/key guessing, or brute-force attacks that can lead to increased costs or reveal misconfigurations. The activity is characterized by a high volume of failed S3 operations (HTTP 403 AccessDenied errors) targeting a specific bucket from a single source IP address within a defined timeframe. Of particular concern is the potential to cause an increase in billing due to internal "AccessDenied" errors, although AWS has announced changes to not charge for 403 errors originating from outside the account/organization. Defenders should prioritize confirming the source of the requests (internal vs. external) and validate the caller's identity. The detection logic relies on AWS CloudTrail logs and is triggered when a threshold of failed operations is exceeded.

## Attack Chain

1.  **Reconnaissance:** The attacker begins by gathering information about potential target S3 buckets, possibly through publicly available information or enumeration techniques.
2.  **Bucket Enumeration:** The attacker attempts to enumerate existing S3 buckets within an AWS environment. This may involve guessing bucket names or using tools to identify publicly accessible buckets.
3.  **Object/Key Guessing:** Once a bucket is identified, the attacker attempts to guess object or key names within the bucket to identify potentially sensitive data.
4.  **Brute-Force Attempts:** The attacker initiates a high volume of requests to the identified bucket, attempting to access various objects or keys using brute-force techniques.
5.  **Access Denied Errors:** Due to insufficient permissions or incorrect object/key names, the majority of these requests result in "AccessDenied" (HTTP 403) errors logged in AWS CloudTrail.
6.  **Cost Inflation (Potential):** If the requests originate from within the AWS account/organization, the failed requests can potentially contribute to increased AWS billing. This is less of a concern for external requests due to a billing change implemented by AWS in August 2024.
7.  **Data Exfiltration Attempt (Possible):** If the attacker successfully identifies accessible objects/keys, they may attempt to exfiltrate sensitive data.
8.  **Impact:** Successful exfiltration of sensitive data can lead to data breaches, financial loss, or reputational damage. Unsuccessful attempts may still cause a denial of service or increased AWS costs.

## Impact

The impact of successful AWS S3 bucket enumeration or brute-force attacks can range from increased AWS costs to data breaches. While AWS no longer charges the bucket owner for AccessDenied errors originating from outside of the AWS account or organization, internal requests can still incur charges. Furthermore, successful identification and exfiltration of sensitive data from S3 buckets can lead to significant financial and reputational damage. The number of affected buckets and severity of the impact depends on the attacker's objectives and the sensitivity of the data stored within the targeted buckets.

## Recommendation

*   Enable AWS CloudTrail data events for S3 buckets to ensure the necessary logging for detection (reference: "data_stream.dataset: aws.cloudtrail").
*   Deploy the Sigma rule "Detect High Volume of AWS S3 AccessDenied Errors" to your SIEM and tune the threshold based on your environment's baseline activity (reference: Sigma rule below).
*   Review and enforce S3 Block Public Access settings to prevent unauthorized access to buckets (reference: Rule documentation mentions Block Public Access).
*   Implement least-privilege IAM policies to restrict access to S3 buckets and objects based on the principle of least privilege (reference: Rule documentation mentions IAM policies).
*   Monitor for unusual PutBucketPolicy, PutPublicAccessBlock, and PutBucketVersioning events in CloudTrail to detect potential tampering of bucket configurations (reference: Rule documentation mentions PutBucketPolicy).
*   Investigate any GuardDuty S3 findings related to the targeted buckets or principals to identify potential security issues (reference: Rule documentation mentions GuardDuty S3 findings).
