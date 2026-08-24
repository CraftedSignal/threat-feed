---
title: Detection of Unauthorized AWS Secrets Manager Credential Retrieval
slug: 2026-08-aws-secrets-access
description: An adversary who has compromised an AWS service instance, such as EC2 or Lambda, may leverage assigned IAM roles to programmatically retrieve sensitive credentials from AWS Secrets Manager using the GetSecretValue API.
date: "2026-08-24T09:45:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Amazon
products:
  - AWS Secrets Manager
  - AWS EC2
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: An adversary with access to a compromised AWS service... may attempt to leverage the compromised service to access secrets in AWS Secrets Manager.
    confidence_band: high
rules:
  - title: Detect First Time Seen AWS Secret Value Accessed in Secrets Manager
    description: Detects the first time a specific user identity has successfully retrieved a secret value from AWS Secrets Manager using the GetSecretValue API.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.006
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security Team
  immediate_actions:
    - action: Review IAM policies for EC2/Lambda roles that have GetSecretValue permissions
      owner: Cloud Security Team
      due: 48h
      evidence: Source recommendations for response and remediation
  hunt_leads:
    - lead: Search CloudTrail for anomalous GetSecretValue events from non-standard user agents
      technique_id: T1555.006
      data_needed:
        - CloudTrail user_agent.original
        - CloudTrail source.ip
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Investigate abnormal values in the user_agent.original field
  mitigation_plan:
    - priority: short_term
      action: Enable MFA for all IAM users and roles where applicable
      owner: Cloud Security Team
      addresses: Unauthorized credential access
      evidence: Source best practice recommendations
---

Adversaries with initial access to AWS environments often target AWS Secrets Manager to escalate privileges or move laterally. By compromising service-linked identities - such as those assigned to EC2 instances or Lambda functions - attackers can invoke the GetSecretValue API to extract credentials that were intended to replace hardcoded secrets. This behavior represents a significant risk, as legitimate service roles may possess broad permissions to access multiple secrets. Defenders should monitor for anomalous or first-time programmatic access to secret values by specific user identities. Monitoring CloudTrail logs for the GetSecretValue action, while filtering out known service role activity, provides visibility into potential credential harvesting attempts. Because this activity is often performed programmatically, inspecting user agent strings and source IP addresses against historical baselines is essential for identifying unauthorized access.

## Attack Chain

1. Attacker gains initial access to a cloud-resident asset such as an EC2 instance or Lambda function.
2. Attacker enumerates available IAM permissions to identify access to AWS Secrets Manager.
3. Attacker discovers target secret identifiers via service enumeration or local configuration file analysis.
4. Attacker executes the GetSecretValue API call using the compromised instance's IAM role credentials.
5. Attacker retrieves the cleartext secret value or sensitive configuration data returned by the API.
6. Attacker utilizes the harvested credentials to access additional internal services or databases.
7. Attacker maintains persistence or performs further data exfiltration using the compromised credentials.

## Impact

Successful exploitation allows attackers to gain unauthorized access to databases, third-party services, and other high-value infrastructure. The impact includes potential data exfiltration, unauthorized administrative access, and lateral movement across the cloud environment. By harvesting these secrets, an attacker can effectively bypass network-level controls and maintain access even if the initial entry point is secured.

## Recommendation

* Deploy the provided Sigma-compatible detection logic to monitor CloudTrail for unusual GetSecretValue events.
* Audit IAM policies associated with EC2 and Lambda service roles to ensure the principle of least privilege is strictly applied to Secrets Manager access.
* Establish baselines for service-to-secret mapping to reduce the noise of legitimate programmatic access.
* Review CloudTrail logs for anomalous user agents (e.g., non-SDK, manual CLI usage) associated with GetSecretValue actions.
* Enable multi-factor authentication for all IAM users and limit the scope of long-lived access keys where possible.
