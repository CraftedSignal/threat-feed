---
title: Detecting Unauthorized AWS EC2 Instance Creation via Instance Type Anomalies
slug: 2026-10-cloud-compute-instance-unseen-type
description: This detection brief identifies potential unauthorized AWS resource provisioning by monitoring for the creation of EC2 instance types that have not been previously observed in an organization's environment.
date: "2026-10-05T12:06:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - cloud-security
  - anomaly-detection
vendors:
  - Amazon
products:
  - EC2
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: The following analytic detects the creation of EC2 instances with previously unseen instance types.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/cloud_compute_instance_created_with_previously_unseen_instance_type.yml
---

This threat detection identifies anomalies in AWS compute infrastructure provisioning, specifically the creation of EC2 instances utilizing instance types that deviate from the organization's historical baseline. Monitoring for previously unseen instance types is a critical capability for security operations centers, as attackers frequently abuse cloud environments to provision powerful, high-compute instances for illicit activities such as cryptomining or building out unauthorized command-and-control infrastructure.

The detection logic relies on maintaining a baseline of known instance types and comparing current AWS CloudTrail events against this historical record. By identifying deviations, defenders can investigate whether new instance types represent authorized architectural expansion or malicious activity. Given the potential for false positives caused by legitimate administrative changes, each alert requires manual verification with the relevant infrastructure or development teams to confirm the business necessity of the new instance type.

## Impact

Successful unauthorized resource provisioning can lead to significant financial costs, data exfiltration, system compromise, or service disruption. In scenarios involving cryptomining, attackers exploit the elasticity of cloud environments to consume resources rapidly, often leading to performance degradation of production systems and unexpected billing spikes.

## Recommendation

* Baseline your environment by running the "Previously Seen Cloud Compute Instance Types - Initial" and "Previously Seen Cloud Compute Instance Types - Update" searches to populate the lookup table.
* Enable alerts for new instance type creation and verify with IT administrators if the instantiation was intentional.
* Integrate the provided logic into your SIEM to monitor AWS CloudTrail logs for unexpected `RunInstances` or `CreateInstances` API calls.
* Customize the `cloud_compute_instance_created_with_previously_unseen_instance_type_filter` macro to exclude known service accounts or automated deployment pipelines that regularly introduce new instance configurations.
