---
title: GCP Service Account Impersonation Role Grant Detection
slug: 2026-08-gcp-sa-impersonation
description: Adversaries can gain unauthorized access to Google Cloud Platform environments by granting themselves service account impersonation roles, enabling long-term persistence and privilege escalation that survives credential rotation.
date: "2026-08-11T23:43:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - cloud-security
  - gcp
vendors:
  - Google
products:
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries abuse these grants to pivot to a higher-privileged identity, escalate privileges, and persist in a way that is unaffected by key rotation or password resets.
    confidence_band: high
references:
  - https://cloud.google.com/iam/docs/service-account-impersonation
  - https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/backdooring-service-account/
  - https://stratus-red-team.cloud/attack-techniques/GCP/gcp.persistence.backdoor-service-account-policy/
rules:
  - title: Detect GCP IAM Service Account Impersonation Role Granted
    description: Detects when a service account impersonation role (e.g., serviceAccountTokenCreator) is added to a service account via SetIamPolicy.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098.003
    data_sources:
      - process_creation
      - google_cloud
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to identify service account impersonation grants.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in source.
  hunt_leads:
    - lead: Identify all service accounts with roles/iam.serviceAccountUser or similar impersonation roles currently bound.
      technique_id: T1098.003
      data_needed:
        - GCP IAM Policy exports
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Review existing bindings to identify unauthorized or stale access.
  mitigation_plan:
    - priority: immediate
      action: Review and audit all current service account IAM policies for unauthorized impersonation bindings.
      owner: Cloud Security Team
      addresses: Persistent access via cloud roles
      evidence: Source recommendations for remediation.
---

Adversaries with sufficient GCP administrative privileges can establish durable, key-less persistence by granting themselves or an attacker-controlled principal specific IAM roles on a target service account. The roles `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser`, and `roles/iam.serviceAccountOpenIdTokenCreator` allow a principal to mint OAuth2 access tokens, generate OpenID Connect identity tokens, or attach (actAs) the target service account to new cloud resources. Because these roles leverage GCP's native IAM trust relationship rather than long-lived static service account keys, the resulting access is unaffected by traditional credential rotation or password reset procedures. This technique is commonly used to pivot from a compromised low-privileged identity to a higher-privileged service account with broader project or organization-level permissions. Defenders should monitor for unexpected `SetIamPolicy` operations, particularly when the principal performing the grant has not historically performed such actions.

## Impact

Successful exploitation allows an adversary to maintain long-term access to a GCP environment regardless of security team efforts to rotate credentials. It facilitates significant privilege escalation if the target service account possesses broad IAM permissions. In enterprise environments, this can lead to unauthorized data access, infrastructure manipulation, and cross-project movement within the GCP organization.

## Recommendation

* Deploy detection rules to monitor `SetIamPolicy` operations that add impersonation roles to service accounts.
* Baseline administrative and CI/CD service accounts (such as Terraform or Jenkins) that legitimately perform IAM modifications to reduce false positives.
* Restrict the ability to set IAM policies on service accounts and implement a peer-review or justification-based approval process for IAM changes.
* Review existing IAM bindings for unauthorized principals or external accounts that have been granted impersonation rights.
