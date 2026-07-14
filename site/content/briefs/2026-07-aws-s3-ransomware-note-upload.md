---
title: Potential AWS S3 Bucket Ransomware Note Uploaded
slug: 2026-07-aws-s3-ransomware-note-upload
description: Adversaries exploit misconfigured AWS S3 buckets or compromised credentials to upload ransomware notes, often after deleting or encrypting data, aiming to extort victims.
date: "2026-07-14T07:38:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - s3
  - ransomware
  - impact
  - data-destruction
vendors:
  - Amazon
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries with access to a misconfigured S3 bucket may retrieve, delete, and replace objects with ransom notes to extort victims.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Attackers who obtain credentials or abuse overly-permissive bucket policies can upload ransom notes (often after deleting or encrypting data).
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: This rule detects the PutObject S3 API call with an object name commonly associated with ransomware notes. Adversaries with access to a misconfigured S3 bucket may retrieve, delete, and replace objects with ransom notes to extort victims.
    confidence_band: high
references:
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-batch-deletion/
  - https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
  - https://www.mdpi.com/2073-431X/10/11/145#computers-10-00145-f002
rules:
  - title: Potential AWS S3 Bucket Ransomware Note Uploaded
    description: Identifies potential ransomware notes being uploaded to an AWS S3 bucket by detecting the PutObject S3 API call with object names commonly associated with ransomware notes.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
      - T1486
      - T1565
      - T1565.001
    data_sources:
      - cloudtrail
      - aws
      - s3
rules_count: 1
---

This threat involves the detection of potential ransomware activity targeting Amazon S3 buckets. Threat actors, having gained unauthorized access to an AWS environment either through compromised credentials or by exploiting misconfigured S3 bucket policies, will manipulate or delete data stored within the buckets. Following data destruction or encryption, they proceed to upload objects with filenames commonly associated with ransomware notes, such as "HOW_TO_DECRYPT.txt" or "RECOVER_YOUR_FILES.html". This action is performed via the `PutObject` S3 API call, leaving a digital demand for ransom as a final step in their extortion attempt. The detection mechanism focuses on these specific filename patterns, which are rarely encountered in legitimate S3 operations, indicating a high-confidence threat scenario that impacts data availability and integrity for targeted organizations.

## Attack Chain

1. **Initial Access**: Threat actor compromises AWS credentials (e.g., IAM user access key) or identifies a publicly exposed/misconfigured S3 bucket.
2. **Discovery**: Attacker enumerates accessible S3 buckets and identifies those containing valuable data, assessing their permissions and configurations.
3. **Privilege Escalation (Optional)**: If initial access is limited, the attacker may attempt to escalate privileges to gain `s3:DeleteObject`, `s3:PutObject`, or other critical permissions on target buckets.
4. **Data Manipulation/Exfiltration**: Attacker may exfiltrate sensitive data from the S3 bucket before proceeding with destructive actions.
5. **Data Destruction/Encryption**: Attacker deletes existing objects, or overwrites them with encrypted versions, rendering original data inaccessible. This is performed via `s3:DeleteObject` or `s3:PutObject` operations.
6. **Ransom Note Upload**: Attacker uploads files with characteristic ransomware note filenames (e.g., `README_TO_DECRYPT.txt`, `_RANSOM_NOTE_.html`) into the affected S3 bucket(s) using the `s3:PutObject` API call.
7. **Impact Notification**: Victims discover data loss and the uploaded ransom notes, signaling the successful compromise and impact.
8. **Extortion**: The attacker initiates contact or awaits victim response, demanding cryptocurrency for data recovery or decryption keys.

## Impact

Successful attacks result in significant data loss, operational disruption, and financial costs due to extortion demands and recovery efforts. Organizations across all sectors utilizing AWS S3 for data storage are potential targets. The primary impact is the unavailability of critical data, which can halt business operations, damage reputation, and lead to regulatory fines if sensitive information is lost or compromised. While specific victim counts are not provided, any organization with a misconfigured or compromised S3 environment is vulnerable to this type of attack, leading to potential multi-million dollar recovery costs.

## Recommendation

* Deploy the Sigma rule "Potential AWS S3 Bucket Ransomware Note Uploaded" to your SIEM and tune for your environment to detect `PutObject` calls with ransom keywords.
* Ensure AWS S3 data events are enabled in your CloudTrail trail configuration to capture `PutObject` API calls, which are critical for the rule's functionality.
* Review and harden S3 bucket policies, enabling "Block Public Access" and configuring least privilege access to `PutObject` and `DeleteObject` actions, as referenced in the provided AWS S3 documentation.
* Implement S3 Versioning and MFA-Delete on critical buckets to provide recovery options and prevent unauthorized deletion, as detailed in the AWS Customer Playbook.
* Investigate alerts from the "Potential AWS S3 Bucket Ransomware Note Uploaded" rule by reviewing `aws.cloudtrail.user_identity.*`, `source.ip`, `user.agent`, and `aws.cloudtrail.request_parameters` to confirm the actor and context of the upload.
