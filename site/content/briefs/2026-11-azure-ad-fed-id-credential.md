---
brief_id: brief-2026-11-03-azure-ad-fed-id-credential
event_id: brief-2026-11-03-azure-ad-fed-id-credential
revision: 1
activity_at: "2026-11-03T15:16:32Z"
title: 'Azure AD: Federated identity credential addition to service principal'
slug: 2026-11-azure-ad-fed-id-credential
description: Adversaries may abuse Entra ID federated identity credentials to establish persistent, secretless authentication by pointing credentials to a controlled OIDC issuer.
date: "2026-11-03T15:16:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against Splunk ESCU detection logic.
tags:
  - azure-ad
  - persistence
  - cloud-security
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098.001
    technique_name: Additional Cloud Credentials
    evidence: If an attacker adds a federated credential pointing to a controlled OIDC issuer, they gain a persistent secretless authentication path into the SP that survives credential rotations and is not visible in standard secrets monitoring.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.004
    technique_name: Cloud Accounts
    evidence: Workload identity federation allows external OIDC workloads such as GitHub Actions or Kubernetes to authenticate as the SP without a secret.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
  - https://attack.mitre.org/techniques/T1098/001/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/azure_ad_federated_identity_credential_added_to_service_principal.yml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Search Azure AD AuditLogs for operations 'Update application' or 'Update service principal' where the modifiedProperty displayName is 'FederatedIdentityCredentials'.
      technique_id: T1098.001
      data_needed:
        - Azure Active Directory AuditLogs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The analytic leverages Azure Active Directory AuditLogs for the 'Update service principal' or 'Update application' operations and filters on the FederatedIdentityCredentials modifiedProperty.
  mitigation_plan:
    - priority: medium
      action: Review all service principals with federated identity credentials and verify the OIDC issuers against a list of approved providers.
      owner: Identity Management
      addresses: T1098.001
---

Attackers can leverage the Entra ID (formerly Azure AD) workload identity federation feature to gain persistent access to service principals. By adding a new federated identity credential that points to an attacker-controlled OIDC issuer, a threat actor can authenticate as the service principal without requiring client secrets. This technique evades standard secrets monitoring and persists across credential rotations.

## Impact
Successful exploitation grants an attacker a persistent, secretless authentication path to the target service principal, potentially allowing for lateral movement, privilege escalation, or access to cloud resources protected by the service principal identity.

## Recommendation
- Baseline existing federated identity credentials across all service principals to identify legitimate OIDC configurations.
- Implement monitoring for the addition of new federated identity credentials, specifically focusing on unknown or unapproved OIDC issuers.
- Audit existing service principals for overly permissive subject claims in federated credentials.
- Use the hunt lead provided in the action plan to investigate current environment activity.
