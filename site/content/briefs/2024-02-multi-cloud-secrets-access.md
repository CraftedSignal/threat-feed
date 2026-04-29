---
title: Multiple Cloud Secrets Accessed by Single Source IP
slug: 2024-02-multi-cloud-secrets-access
description: A single source IP accessing secret-management APIs across multiple cloud providers (AWS, GCP, Azure) and Kubernetes clusters within a short timeframe indicates potential credential theft, session hijacking, or token replay.
date: "2026-04-10T16:27:52Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - credential-access
  - cloud
  - kubernetes
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
  - title: Multiple Cloud Secrets Accessed by Source Address
    description: Detects a single source IP accessing secret-management APIs across multiple cloud providers (AWS, GCP, Azure) and Kubernetes clusters.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.006
    data_sources:
      - network_connection
      - cloudtrail|azure|gcp|kubernetes
  - title: Multiple Cloud Secrets Accessed by User Agent
    description: Detects multiple cloud secrets accessed by the same user agent in different cloud environments
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.006
    data_sources:
      - webserver
      - linux|windows
rules_count: 2
---

This threat brief focuses on the detection of potential credential compromise and abuse in multi-cloud environments. The core issue is the observation of a single source IP address accessing secret stores across multiple cloud providers (AWS Secrets Manager, Google Secret Manager, Azure Key Vault) and Kubernetes clusters within a short timeframe. This behavior, detected by the Elastic rule "Multiple Cloud Secrets Accessed by Source Address" published on 2026-04-10, is indicative of an adversary attempting to harvest secrets using stolen credentials, hijacked sessions, or replayed tokens. The rule is designed to identify anomalous cross-cloud secret retrieval, which is uncommon in legitimate multi-cloud orchestration scenarios. Defenders need to identify the source IP, the accessed secrets, and potential compromise scope to mitigate the threat effectively.

## Attack Chain

1.  **Initial Access:** Adversary gains access to valid credentials or session tokens through various means like phishing, malware, or exposed credentials. (T1555, T1566)
2.  **Authentication:** Adversary uses the compromised credentials or tokens to authenticate to one of the cloud provider's API (AWS, Azure, GCP).
3.  **Discovery (AWS):** The adversary leverages the AWS CLI or API to enumerate available secrets stored in AWS Secrets Manager using `GetSecretValue` API calls.
4.  **Discovery (Azure):** The adversary uses compromised credentials to interact with Azure Key Vault, utilizing `SecretGet` or `KeyGet` actions to discover accessible secrets.
5.  **Discovery (GCP):** The adversary uses compromised service account or user credentials to access Google Secret Manager and enumerate accessible secrets using `google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion` or `google.cloud.secretmanager.v1.SecretManagerService.GetSecretRequest`.
6.  **Discovery (Kubernetes):** The adversary uses compromised credentials to access the Kubernetes API and enumerate secrets within the cluster, specifically targeting the `secrets` resource with `get` or `list` verbs.
7.  **Credential Access:** The adversary retrieves the secret values from each cloud provider and Kubernetes cluster. (T1555.006)
8.  **Exfiltration/Lateral Movement:** The adversary exfiltrates the retrieved secrets for further malicious activities, such as lateral movement within the cloud environments or unauthorized access to sensitive data.

## Impact

A successful attack can lead to the exfiltration of sensitive data, including API keys, database passwords, and encryption keys. This could result in unauthorized access to critical systems and data, potentially leading to data breaches, financial loss, and reputational damage. The impact is amplified in multi-cloud environments as the adversary can leverage the compromised secrets to move laterally between different cloud providers, increasing the scope and severity of the attack.

## Recommendation

*   Deploy the provided Sigma rule "Multiple Cloud Secrets Accessed by Source Address" to your SIEM to detect this activity across your cloud environments. Enable required logging: GCP Audit DATA_READ for Secret Manager API, Azure Key Vault Diagnostic Logging, and AWS CloudTrail for Secrets Manager.
*   Investigate any alerts triggered by the Sigma rule by validating the principal (user, service account) and reviewing related activity (authentication, privilege escalation). Check application context, user agent, and IP reputation as detailed in the rule's triage steps.
*   Restrict or disable affected credentials or service accounts and rotate all accessed secrets if the activity is unauthorized or suspicious, as described in the rule's Response and Remediation steps.
*   Harden identity security by enforcing MFA, reducing permissions to least privilege, and reviewing trust relationships. Audit visibility should be improved by ensuring logging is enabled across all cloud environments.
