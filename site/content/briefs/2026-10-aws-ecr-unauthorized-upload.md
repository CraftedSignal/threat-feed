---
title: Detection of Unauthorized Container Image Uploads to AWS ECR
slug: 2026-10-aws-ecr-unauthorized-upload
description: This detection identifies potential unauthorized container image pushes to AWS ECR by monitoring for 'PutImage' API calls from users not present in an established allowlist, a common indicator of supply chain or lateral movement activity.
date: "2026-10-14T02:18:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - container-security
  - supply-chain
vendors:
  - Amazon
products:
  - Elastic Container Registry (ECR)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The detection monitors PutImage calls which is associated with MITRE ATT&CK technique T1204.003 regarding the potential introduction of malicious images.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1204/003/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/asl_aws_ecr_container_upload_unknown_user.yml
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Establish an authorized user allowlist for AWS ECR repository access
      owner: SOC
      due: 72h
      evidence: Required for the effectiveness of the ASL AWS ECR container upload detection
  hunt_leads:
    - lead: Identify all successful PutImage operations from accounts not previously observed in ECR activity logs
      technique_id: T1204.003
      data_needed:
        - AWS CloudTrail API events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Detection logic flags anomalous PutImage actions
  mitigation_plan:
    - priority: medium
      action: Enable AWS ECR enhanced scanning for pushed images
      owner: IT Operations
      addresses: Supply chain risks via compromised container images
      evidence: Industry best practice for container registry security
---

This brief focuses on identifying anomalous container image management activity within Amazon Web Services (AWS) environments, specifically targeting unauthorized pushes to the AWS Elastic Container Registry (ECR). Adversaries or malicious insiders may attempt to push malicious or backdoored container images into a registry to facilitate downstream execution, persistence, or lateral movement within a containerized CI/CD pipeline or orchestration environment. By monitoring AWS CloudTrail logs via Amazon Security Lake, security teams can isolate instances where the 'PutImage' API operation is invoked by identities not previously categorized as authorized developers or automated build systems. This approach provides visibility into potential supply chain compromise attempts.

## Impact

Successful exploitation could result in the deployment of compromised or malicious container images across an organization's infrastructure. Unauthorized images may contain backdoors, malware, or hardcoded credentials, leading to full container escapes, data exfiltration, or secondary access within the cloud environment. Organizations leveraging automated deployment pipelines are particularly vulnerable to these malicious images being automatically promoted to production clusters.

## Recommendation

- Maintain and regularly update an allowlist of authorized IAM entities (users, roles, and service accounts) permitted to push images to production ECR repositories.
- Ingest AWS CloudTrail logs via Amazon Security Lake into your SIEM to monitor for 'PutImage' API activity.
- Establish alerting thresholds for 'PutImage' events originating from source IP addresses or user agents outside of known developer workstations or CI/CD runner environments.
- Implement and enforce ECR image scanning to detect known vulnerabilities in images before they are deployed to orchestration platforms.
