---
title: Cloud Compute Instance Created with Previously Unseen Image
slug: 2024-01-25-cloud-instance-unseen-image
description: A cloud compute instance was created with a previously unseen image, potentially indicating malicious activity such as unauthorized deployment or image compromise.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - compute-instance
  - image-compromise
vendors:
  - Amazon
  - Microsoft
  - Google
products:
  - Amazon Web Services
  - Azure
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1587
    technique_name: Develop Capabilities
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/cloud_compute_instance_created_with_previously_unseen_image.yml
rules:
  - title: Cloud Instance Created with Unseen Image
    description: Detects the creation of a cloud compute instance using a previously unseen image.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1587.001
    data_sources:
      - cloudtrail
      - aws
  - title: Azure VM Created with Unseen Image
    description: Detects the creation of an Azure Virtual Machine using a previously unseen image.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1587.001
    data_sources:
      - azure_activity
      - azure
rules_count: 2
---

This alert focuses on detecting the creation of cloud compute instances using previously unseen images within a cloud environment. The use of a new or unknown image could signal various malicious activities, including unauthorized deployment of resources, use of compromised images containing malware, or attempts to bypass security controls. While the provided content does not specify a threat actor, a successful attack involving a rogue image can lead to significant data breaches, resource hijacking, and operational disruption. It is crucial for defenders to identify and investigate such instances promptly to prevent further damage. The scope of this alert is applicable to any cloud environment that supports compute instance creation from images.

## Attack Chain

1.  An attacker gains unauthorized access to a cloud account or obtains valid credentials via credential stuffing or phishing.
2.  The attacker uploads a malicious or compromised image to the cloud environment's image repository or leverages a publicly available, but malicious image.
3.  The attacker uses the cloud provider's API or management console to initiate the creation of a new compute instance.
4.  During instance creation, the attacker specifies the previously unseen image as the source image for the new instance.
5.  The cloud provider provisions the new compute instance using the specified image.
6.  The attacker connects to the newly created instance and executes malicious code or uses it for lateral movement within the cloud environment.
7.  The attacker exploits resources within the compromised instance to steal sensitive data or compromise other cloud resources.

## Impact

Compromised cloud compute instances can lead to data breaches, resource hijacking for cryptocurrency mining, and the deployment of malicious applications. A single compromised instance can serve as a beachhead for lateral movement, potentially impacting a large number of resources within the cloud environment. The use of rogue images bypasses standard image vetting procedures, increasing the likelihood of a successful attack.

## Recommendation

*   Implement the provided Sigma rule `Cloud Instance Created with Unseen Image` to detect when a new compute instance is created using an image that has not been previously observed in your environment. Tune the rule to your specific environment and baselines.
*   Enable and monitor cloud provider logs related to compute instance creation and image usage to provide the data source for the Sigma rule above (CloudTrail, Azure Activity Log, GCP Cloud Logging).
*   Implement strict image vetting procedures, including regular scanning for vulnerabilities and malware, to reduce the risk of deploying compromised images.
