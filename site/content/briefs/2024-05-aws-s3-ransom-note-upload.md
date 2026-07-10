---
title: Potential AWS S3 Bucket Ransomware Note Upload
slug: 2024-05-aws-s3-ransom-note-upload
description: An adversary may upload a ransomware note to an AWS S3 bucket by abusing compromised credentials or overly permissive bucket policies, potentially leading to data encryption or exfiltration.
date: "2024-05-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - s3
  - ransomware
  - impact
vendors:
  - AWS
products:
  - S3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_s3_bucket_object_uploaded_with_ransom_keyword.toml
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-batch-deletion/
  - https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
  - https://www.mdpi.com/2073-431X/10/11/145#computers-10-00145-f002
rules:
  - title: Detect AWS S3 Ransom Note Upload
    description: Detects the upload of a file to an AWS S3 bucket with a name commonly associated with ransomware notes.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS S3 Bucket Policy Modification
    description: Detects changes to S3 bucket policies, which could be indicative of an attacker attempting to make the ransom note public.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1565.001
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS S3 DeleteObject
    description: Detects deletion of objects in AWS S3 bucket, which could be indicative of data destruction before the ransom note.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
rules_count: 3
---

This detection identifies the potential upload of ransomware notes to an AWS S3 bucket, indicating a possible ransomware attack targeting cloud storage. The alert triggers on `PutObject` API calls where the object key (filename) matches patterns commonly associated with ransomware notes (e.g., "readme", "decrypt"). Attackers might gain unauthorized access to S3 buckets through compromised credentials or misconfigured bucket policies, enabling them to delete, encrypt, or replace existing objects with ransom notes, threatening data exfiltration or destruction if demands are unmet. The scope includes organizations utilizing AWS S3 for data storage, especially those with publicly accessible or poorly secured buckets. This activity was observed being tested by red teams to emulate ransomware activity as recent as April 2024.

## Attack Chain

1. **Initial Access:** An attacker gains access to AWS credentials through phishing, credential stuffing, or exploiting vulnerabilities in applications with AWS access.
2. **Privilege Escalation (Optional):** The attacker escalates privileges within the AWS environment to gain access to S3 buckets.
3. **Bucket Discovery:** The attacker identifies accessible S3 buckets through reconnaissance and enumeration techniques.
4. **Data Exfiltration/Encryption (Optional):** Prior to the ransom note, the attacker may exfiltrate sensitive data or encrypt objects within the S3 bucket using tools like `awscli`.
5. **Ransom Note Upload:** The attacker uploads a ransom note to the S3 bucket using the `PutObject` API call. The object key (filename) contains keywords like "readme", "decrypt", or "ransom".
6. **Bucket Policy Modification (Optional):** The attacker may modify the bucket policy using `PutBucketPolicy` to restrict access or make the ransom note publicly accessible.
7. **Impact:** The organization discovers the ransom note, indicating a potential ransomware attack. Data exfiltration, encryption, or deletion may have occurred, leading to business disruption and financial losses.

## Impact

A successful attack can lead to significant data loss, business interruption, and reputational damage. While there are no specific victim numbers available, organizations across various sectors using AWS S3 are potentially vulnerable. The impact ranges from temporary service outages due to encrypted or deleted data to long-term financial losses associated with data recovery and ransom payments. The criticality depends on the sensitivity and importance of the data stored within the compromised S3 bucket.

## Recommendation

*   Deploy the Sigma rule "Detect AWS S3 Ransom Note Upload" to your SIEM to identify potential ransomware attacks targeting S3 buckets. Tune the rule for your environment to reduce false positives.
*   Enable AWS CloudTrail data events for S3 buckets to capture `PutObject` API calls and other relevant activities as required by the Sigma rule.
*   Review S3 bucket policies to ensure least privilege access and restrict public access where possible.
*   Implement multi-factor authentication (MFA) for all AWS accounts and users to protect against credential compromise.
*   Enable S3 Versioning and Object Lock to protect data from deletion or modification and facilitate recovery as described in the overview.
*   Monitor for suspicious IAM activity, such as new access keys or policy changes, to detect potential privilege escalation or lateral movement.
