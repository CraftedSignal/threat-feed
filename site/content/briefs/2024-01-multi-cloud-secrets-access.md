---
title: Multiple Cloud Secrets Accessed by Source Address
slug: 2024-01-multi-cloud-secrets-access
description: A single source IP accessing secret-management APIs across multiple cloud providers (AWS, GCP, Azure) and Kubernetes clusters within a short timeframe indicates credential theft or token replay for secret harvesting.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - credential-access
  - kubernetes
vendors:
  - AWS
  - Google
  - Microsoft
  - Kubernetes
products:
  - AWS Secrets Manager
  - Google Secret Manager
  - Azure Key Vault
  - Kubernetes Secrets
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
  - https://docs.cloud.google.com/secret-manager/docs/samples/secretmanager-access-secret-version
  - https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets
  - https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
rules:
  - title: Multiple Cloud Secrets Accessed by Source IP
    description: Detects a single source IP accessing secret-management APIs across multiple cloud providers.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.006
    data_sources:
      - network_connection
      - windows
  - title: Kubernetes Secret Accessed After Cloud Secret
    description: Detects Kubernetes secret access following cloud secret access from the same source.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection identifies instances where a single source IP address accesses secret-management APIs across multiple cloud environments, including AWS Secrets Manager, Google Secret Manager, Azure Key Vault, and Kubernetes Secrets. This activity, occurring within a short timeframe, is indicative of potential credential theft, session hijacking, or token replay. Attackers with compromised credentials may attempt to rapidly retrieve secrets to expand access or exfiltrate sensitive information. The rule leverages data from AWS CloudTrail, Azure platform logs, GCP audit logs, and Kubernetes audit logs. Defenders should investigate unexpected cross-cloud secret retrieval, as it is uncommon and typically points to automation misuse or malicious activity. This detection helps identify and respond to threats involving stolen authenticated sessions used to harvest secrets across diverse cloud environments.

## Attack Chain

1.  Attacker gains initial access through credential theft, session hijacking, or token replay.
2.  Compromised credentials are used to authenticate to one of the cloud provider environments (AWS, Azure, or GCP).
3.  The attacker leverages the compromised credentials to access the secret management service (e.g., AWS Secrets Manager, Azure Key Vault, Google Secret Manager).
4.  The attacker retrieves secrets using API calls such as GetSecretValue (AWS), SecretGet/KeyGet (Azure), or AccessSecretVersion (GCP).
5.  The attacker pivots and uses the same compromised credentials or session to access secret management services in other cloud provider environments.
6.  The attacker retrieves secrets from the additional cloud environments, demonstrating cross-cloud access.
7.  The attacker may exfiltrate the harvested secrets or use them to escalate privileges within the compromised cloud environments.
8.  The attacker maintains persistence and expands their access by leveraging the retrieved secrets to compromise additional resources and services.

## Impact

Compromised credentials and harvested secrets can lead to significant data breaches, unauthorized access to sensitive resources, and privilege escalation within cloud environments. Successful attacks can result in the exposure of sensitive data, including API keys, database passwords, and encryption keys, potentially impacting thousands of organizations. The Wiz.io blog post referenced in the rule, "Shai Hulud 2.0: Ongoing Supply Chain Attack," underscores the potential for supply chain compromise through secret harvesting.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM and tune for your environment to detect suspicious cross-cloud secret retrieval activity.
*   Enable DATA_READ logging for the Secret Manager API service in GCP to provide the necessary data for detection.
*   Enable Diagnostic Logging for the Key Vault Service in Azure to capture secret access events.
*   Review IAM permissions and restrict secret access to least privilege across all cloud environments to limit the impact of credential compromise.
*   Implement multi-factor authentication (MFA) for users where applicable to enhance identity security and prevent credential theft.
*   Rotate all accessed secrets and review other secrets the identity can access if compromise is suspected, as described in the rule's response and remediation steps.
