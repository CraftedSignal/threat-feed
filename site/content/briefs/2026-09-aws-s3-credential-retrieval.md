---
title: Unauthorized Access to Sensitive Files in AWS S3
slug: 2026-09-aws-s3-credential-retrieval
description: This detection brief addresses the risk of unauthorized access to sensitive credential and secret files stored in AWS S3 buckets, a common tactic for credential harvesting and lateral movement.
date: "2026-09-18T13:02:32Z"
lastmod: "2026-09-19T13:18:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - credential-access
  - aws
  - exfiltration
  - s3
  - cloud
  - discovery
  - impact
  - collection
vendors:
  - Amazon
products:
  - AWS S3
  - Amazon S3
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
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Threat actors have been observed using these tools for their intuitive interface and bulk data transfer capabilities during post-compromise data theft operations.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1657
    technique_name: Financial Theft
    evidence: This activity can indicate attempts to collect bucket objects or cause an increase in billing to an account via internal AccessDenied errors.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: Identifies a high number of failed S3 operations against a single bucket... This activity can indicate attempts to collect bucket objects.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1619
    technique_name: Cloud Storage Object Discovery
    evidence: This activity can indicate attempts to collect bucket objects or cause an increase in billing.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_credentials_in_s3_bucket.toml
  - https://s3browser.com/
  - https://cyberduck.io/
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
  - https://attackevals.github.io/ael/enterprise/scattered_spider/emulation_plan/scattered_spider_scenario/
  - https://medium.com/@maciej.pocwierz/how-an-empty-s3-bucket-can-make-your-aws-bill-explode-934a383cb8b1
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ErrorCodeBilling.html
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
  - title: Detect AWS API Activity from Uncommon S3 Client
    description: Detects successful AWS S3 API activity originating from S3 Browser or Cyberduck, which are often used for bulk data exfiltration.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - webserver
  - title: Detect AWS S3 Bucket Enumeration or Brute Force
    description: Detects a high volume of 403 AccessDenied errors against a single S3 bucket from a single source, indicating potential enumeration or cost-driven attacks.
    platform: sigma
    severity: low
    tactics:
      - discovery
      - impact
    techniques:
      - T1580
      - T1619
      - T1657
    data_sources:
      - webserver
rules_count: 3
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
updates:
  - at: "2026-09-18T19:33:05Z"
    level: L1
    summary: 'added detection rule: Detect AWS API Activity from Uncommon S3 Client'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_s3_uncommon_client_user_agent.toml
  - at: "2026-09-18T19:33:20Z"
    level: L1
    summary: 'added detection rule: Detect AWS S3 Bucket Enumeration or Brute Force'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_aws_s3_bucket_enumeration_or_brute_force.toml
  - at: "2026-09-19T13:18:48Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_credentials_in_s3_bucket.toml
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
