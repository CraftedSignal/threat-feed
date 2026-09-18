---
title: Unauthorized Access to Sensitive Files in AWS S3
slug: 2026-09-aws-s3-credential-retrieval
description: This detection brief addresses the risk of unauthorized access to sensitive credential and secret files stored in AWS S3 buckets, a common tactic for credential harvesting and lateral movement.
date: "2026-09-18T13:02:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - credential-access
  - aws
vendors:
  - Amazon
products:
  - AWS S3
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The rule detects S3 GetObject calls targeting high-value credential and secret files commonly stored in S3 buckets.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Detects successful S3 GetObject calls targeting high-value credential and secret files.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_credentials_in_s3_bucket.toml
rules:
  - title: Detect AWS S3 Credential File Retrieved
    description: Detects S3 GetObject calls targeting common credential and secret files such as .aws/credentials, SSH keys, and .env files.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1530
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Engineering
  immediate_actions:
    - action: Enable S3 Data Events for critical buckets in CloudTrail.
      owner: Cloud Engineering
      due: 48h
      evidence: S3 data event logging is required for this rule.
  hunt_leads:
    - lead: Search for existing GetObject calls on sensitive paths in the last 30 days.
      technique_id: T1552.001
      data_needed:
        - CloudTrail Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Retrospective analysis can uncover past unauthorized retrieval.
  mitigation_plan:
    - priority: immediate
      action: Rotate all credentials identified as stored in public or over-privileged S3 buckets.
      owner: IT Operations
      addresses: Credential exposure
      evidence: Rotate any credentials stored in the accessed object - treat them as compromised.
---

Attackers frequently target cloud storage environments to harvest sensitive files that facilitate lateral movement and persistence. AWS S3 buckets are often misconfigured or over-privileged, leading to the exposure of configuration files (e.g., .aws/credentials, .env), SSH keys, and PEM/PuTTY private keys. This threat brief highlights the importance of monitoring S3 Data Events to detect when these high-value assets are accessed via 'GetObject' calls. Defenders should focus on identifying access by non-automation identities, as legitimate CI/CD pipelines and administrative tools may also retrieve these files. Ensuring that S3 Data Events are explicitly enabled in CloudTrail is a prerequisite for observability, as management plane events do not capture individual object access.

## Impact

Successful retrieval of these credentials can lead to full compromise of the affected AWS identity, unauthorized access to underlying infrastructure, and potential exfiltration of proprietary data or source code. If the retrieved credentials are reused elsewhere, the impact extends beyond the immediate cloud environment to integrated third-party services and local development machines.

## Recommendation

- Enable AWS S3 Data Events in CloudTrail to gain visibility into object-level operations.
- Implement and tune the provided Sigma-compatible detection logic to identify 'GetObject' events targeting sensitive file patterns.
- Audit S3 bucket policies for overly permissive access (e.g., public read or broad IAM permissions).
- Treat all retrieved credential files as compromised; rotate secrets and keys immediately upon detection of unauthorized access.
- Establish a baseline of authorized IAM roles and source IPs for S3 bucket access to reduce false positives from automated CI/CD processes.
