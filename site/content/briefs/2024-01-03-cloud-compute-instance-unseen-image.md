---
title: Cloud Compute Instance Created With Previously Unseen Image
slug: 2024-01-03-cloud-compute-instance-unseen-image
description: This analytic detects the creation of cloud compute instances using previously unseen image IDs, potentially indicating unauthorized or suspicious activity like malicious payload deployment or unauthorized access, leading to data breaches or further cloud environment compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - cloudtrail
  - compute_instance
  - anomaly
vendors:
  - AWS
products:
  - EC2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/cloud_compute_instance_created_with_previously_unseen_image.yml
rules:
  - title: Cloud Compute Instance Created With Previously Unseen Image ID
    description: Detects the creation of a cloud compute instance with a previously unseen image ID based on AWS CloudTrail logs, indicating potential unauthorized activity.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1587.001
    data_sources:
      - cloudtrail
      - aws
  - title: Cloud Compute Instance Created by Non-IAM User
    description: Detects the creation of a cloud compute instance by a user other than an IAM user, potentially indicating an external entity or service account.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1587.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the creation of cloud compute instances using previously unseen image IDs within a cloud environment. The detection leverages cloud infrastructure logs, specifically AWS CloudTrail, to identify the creation of new compute instances using image IDs that have not been previously observed in the environment. This activity is considered significant as it can indicate unauthorized or suspicious activities such as deployment of malicious payloads, lateral movement, or unauthorized access to sensitive resources within the cloud infrastructure. The detection logic relies on maintaining a baseline of previously seen images and alerting on deviations from this baseline. The focus is on AWS CloudTrail logs, using image IDs as a key indicator of potentially malicious compute instance deployment.

## Attack Chain

1.  An attacker gains initial access to the cloud environment, possibly through compromised credentials or exploiting a misconfiguration.
2.  The attacker attempts to create a new cloud compute instance.
3.  The attacker selects or uploads a custom image to be used for the new compute instance. This image may contain malicious software or configurations.
4.  The cloud compute instance creation event is logged in AWS CloudTrail, including the image ID used for the instance.
5.  The detection mechanism identifies the image ID as one not previously seen in the environment.
6.  The detection triggers an alert due to the use of an unseen image ID, highlighting a potentially anomalous or malicious event.
7.  Security analysts investigate the newly created instance and the associated image to determine its legitimacy.
8.  If the instance or image is deemed malicious, remediation actions such as instance termination, image removal, and account lockdown are taken to prevent further compromise.

## Impact

The successful execution of this type of attack can lead to various detrimental impacts, including the deployment of malicious software within the cloud environment, unauthorized access to sensitive data and resources, lateral movement to other parts of the infrastructure, and potential data breaches. The number of affected instances or the scope of the impact is dependent on the attacker's objectives and the extent of their access. Affected sectors include any organization leveraging cloud compute resources, such as e-commerce, finance, healthcare, and government. A successful attack may result in significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Implement and regularly update the baseline search `Previously Seen Cloud Compute Images - Initial` and `Previously Seen Cloud Compute Images - Update` to maintain an accurate record of known image IDs.
*   Deploy the Sigma rule provided below to your SIEM and tune the thresholds based on your environment's specific needs to minimize false positives.
*   Enable AWS CloudTrail logging in all regions to ensure complete visibility of cloud resource creation events, which is critical for the Sigma rule to function.
*   Customize the `cloud_compute_instance_created_with_previously_unseen_image_filter` macro to exclude known-good images or users to reduce noise.
*   Review the risk objects identified in the RBA section to correlate the newly created instance with user activity for improved incident prioritization.
