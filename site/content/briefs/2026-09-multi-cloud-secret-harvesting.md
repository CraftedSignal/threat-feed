---
title: Cross-Environment Secret Harvesting via Cloud APIs
slug: 2026-09-multi-cloud-secret-harvesting
description: Adversaries are utilizing compromised credentials and stolen session tokens to perform rapid, automated secret harvesting across AWS, GCP, Azure, and Kubernetes environments from singular source IP addresses.
date: "2026-09-18T19:08:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - cloud
  - identity-theft
vendors:
  - Amazon
  - Microsoft
  - Google
products:
  - AWS Secrets Manager
  - Azure Key Vault
  - Google Secret Manager
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: This alert identifies a single source IP address accessing secret-management APIs across multiple cloud providers within a short timeframe.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
  - https://docs.cloud.google.com/secret-manager/docs/samples/secretmanager-access-secret-version
  - https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets
  - https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable required audit logging for Secret Manager APIs across AWS, Azure, and GCP.
      owner: IT Operations
      due: 48h
      evidence: Source document setup section defines logging requirements for detection.
  hunt_leads:
    - lead: Search for single source IPs accessing secrets in more than one cloud provider within a 5-minute window.
      technique_id: T1555.006
      data_needed:
        - AWS CloudTrail
        - Azure Platform Logs
        - GCP Audit Logs
        - Kubernetes Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This rule identifies a single source IP address accessing secret-management APIs across multiple cloud providers.
---

Adversaries are increasingly employing cross-cloud secret harvesting techniques to maximize the impact of compromised identity tokens. By leveraging stolen session data, attackers target secret management services including AWS Secrets Manager, Google Secret Manager, Azure Key Vault, and Kubernetes Secrets. This activity is characterized by rapid, programmatic access to these APIs across multiple cloud provider boundaries from a single source IP address, often within a very short timeframe.

This pattern is highly anomalous and strongly indicates credential theft, session hijacking, or automated token replay attacks. Security teams should be particularly concerned when a single principal or IP address exhibits behavior that bridges distinct cloud platforms, as this suggests a sophisticated effort to gain broad, persistent access or to exfiltrate sensitive environment variables, connection strings, and administrative credentials required for lateral movement. The detection of this behavior is critical for identifying potential supply chain compromises or full-scale cloud environment takeovers.

## Attack Chain

1. Initial access is gained through phishing, malware, or session token theft to acquire valid cloud or Kubernetes identity credentials.
2. The attacker initializes an automated script or tool configured to interface with multiple cloud provider SDKs using the stolen credentials.
3. The attacker systematically queries the AWS Secrets Manager API (GetSecretValue) for high-value secrets.
4. The same source IP immediately pivots to query Google Secret Manager (AccessSecretVersion).
5. Simultaneously, the attacker hits the Azure Key Vault API (SecretGet/KeyGet) to harvest additional platform-specific credentials.
6. The attacker targets the Kubernetes API server within the environment to list and retrieve internal cluster secrets (verb: list/get).
7. All stolen secrets are exfiltrated to an attacker-controlled listener or stored locally for subsequent lateral movement.
8. The final objective is achieved by using the aggregated secrets to expand access across the entire multi-cloud estate.

## Impact

Successful exploitation allows attackers to bypass perimeter security, gain persistent access to sensitive databases and infrastructure, and potentially compromise the entire cloud-native supply chain. This results in wide-scale data exfiltration, the loss of administrative control over cloud resources, and the compromise of downstream systems that rely on the stored secrets.

## Recommendation

* Enable and aggregate logs for AWS CloudTrail, Azure Key Vault Diagnostic Logging, and Google Cloud Data Access (DATA_READ for Secret Manager) to ensure visibility into secret retrieval attempts.
* Implement automated alerting for cross-provider secret access as defined in the provided ESQL detection logic.
* Audit identity and access management policies to enforce least privilege, ensuring that service accounts and workload identities are strictly scoped to their required cloud environments.
* Deploy MFA for all cloud console and API access where possible to mitigate the impact of stolen session tokens.
* Review Kubernetes RBAC roles and cluster namespaces to restrict access to sensitive secret objects to authorized pods only.
