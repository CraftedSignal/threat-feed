---
title: Detection of SDK-Based AWS Control Plane Discovery from Suspicious Processes
slug: 2026-09-aws-control-plane-suspicious-process
description: This detection monitors for processes executing from temporary or user-writable directories that perform DNS queries to AWS management endpoints, a pattern frequently utilized by post-exploitation tools to bypass CLI-based security controls.
date: "2026-09-29T16:15:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - discovery
  - aws
  - credential-theft
  - detection-engineering
vendors:
  - Amazon
products:
  - AWS IAM
  - AWS STS
  - AWS SSM
  - AWS Secrets Manager
  - AWS KMS
  - AWS Bedrock
affected_os:
  - Linux
  - macOS
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: Identifies a process running from a temporary or user-writable directory... followed by a network connection to an AWS identity, secrets, or management control plane endpoint.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: This detects credential abuse performed through an AWS SDK... post exploitation malware and supply chain stealers actually use.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/discovery_aws_control_plane_access_by_suspicious_process.toml
  - https://thehackernews.com/2024/11/malicious-pypi-package-fabrice-found.html
  - https://www.sentinelone.com/labs/cloudy-with-a-chance-of-credentials-aws-targeting-cred-stealer-expands-to-azure-gcp/
  - https://www.sysdig.com/blog/ai-assisted-cloud-intrusion-achieves-admin-access-in-8-minutes
  - https://unit42.paloaltonetworks.com/teamtnt-operations-cloud-environments/
  - https://www.sysdig.com/blog/cloud-breach-terraform-data-theft
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy process and network correlation logic to detect AWS SDK-based discovery from non-standard directories.
      owner: Detection Engineering
      due: 72h
      evidence: Source detection rule logic.
  hunt_leads:
    - lead: Search for DNS queries for aws.amazon.com endpoints originating from processes spawned in /tmp or AppData/Local/Temp.
      technique_id: T1526
      data_needed:
        - DNS query logs
        - Process creation telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Characteristic of SDK-based credential theft.
---

Malicious cloud-native post-exploitation tools frequently utilize AWS SDKs (such as boto3, aws-sdk-js, or the Go SDK) to perform reconnaissance and credential theft. Because these tools leverage libraries directly, they bypass traditional security rules that focus exclusively on monitoring the execution of the official AWS CLI binary. Defenders must instead monitor for the behavioral patterns of the calling processes. Specifically, attackers often stage their malicious scripts or binaries within temporary or user-writable directories (e.g., /tmp, /dev/shm, or AppData/Local/Temp) to maintain persistence or avoid detection. This threat brief covers the detection logic for identifying these suspicious processes when they exhibit network communication with AWS control plane endpoints such as AWS IAM, STS, SSM, Secrets Manager, and KMS. This monitoring approach is critical for identifying cloud environment discovery and credential abuse in environments where attackers use custom or off-the-shelf post-exploitation malware.

## Impact

Successful exploitation allows attackers to perform comprehensive reconnaissance of cloud environments, harvest temporary or permanent credentials, and gain unauthorized access to managed resources. Attackers often escalate privileges, exfiltrate secrets, or gain persistent access to sensitive data within AWS workloads. Organizations in cloud-heavy sectors are particularly at risk, with observed incidents demonstrating full administrative access achieved in as little as eight minutes after initial compromise.

## Recommendation

Detection engineering teams should implement monitoring for SDK-based cloud discovery to address the visibility gap left by CLI-name-based detection.

* Deploy the provided detection logic to monitor for processes originating from suspicious directories that resolve AWS control plane endpoints.
* Establish an exception process for CI/CD runners and legitimate build systems that operate in temporary directories to reduce noise.
* In the event of a high-confidence alert, cross-reference process activity with AWS CloudTrail logs to confirm unauthorized API usage.
* Isolate compromised hosts immediately upon detection and rotate all AWS credentials potentially harvested during the incident.
