---
brief_id: brief-2026-11-02-entra-id-graph-enumeration
event_id: brief-2026-11-02-entra-id-graph-enumeration
revision: 1
activity_at: "2026-11-02T15:08:37Z"
title: 'Microsoft Entra ID: Managed Device Client Sign-In to Graph Enumeration'
slug: 2026-11-entra-id-graph-enumeration
description: Identification of a pattern where a non-interactive Microsoft Entra ID client sign-in, characterized by managed device context and an Edge user agent, is followed by the use of the same access token by a scripted client to perform directory enumeration via Microsoft Graph.
date: "2026-11-02T15:08:37Z"
lastmod: "2026-11-03T15:16:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Detection logic verified against documented Azure AD AuditLog schema.
tags:
  - cloud-security
  - identity-threat
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft Graph
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087.004
    technique_name: Cloud Account
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550.001
    technique_name: Application Access Token
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Guest accounts carry inherent restrictions on tenant resource access; elevating to Member removes those restrictions.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.004
    technique_name: Cloud Accounts
    evidence: If confirmed malicious, this activity indicates an attacker is expanding the capabilities of a compromised or attacker-controlled guest account to gain broader access to tenant resources.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586.003
    technique_name: Cloud Accounts
    evidence: This analytic detects when an Azure AD guest user account has its UserType property changed from Guest to Member.
    confidence_band: med
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/discovery_entra_managed_device_client_signin_graph_enumeration.toml
  - https://github.com/dirkjanm/askWAM
  - https://github.com/SpecterOps/AzureHound
  - https://github.com/dafthack/GraphRunner
  - https://github.com/mlcsec/Graphpython
  - https://github.com/splunk/security_content/blob/main/detections/cloud/azure_ad_guest_user_type_changed_to_member.yml
  - https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions
  - https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity Team
  hunt_leads:
    - lead: Identify Azure AD users elevated from Guest to Member status
      technique_id: T1098
      data_needed:
        - Azure Active Directory AuditLogs (operationName="Update user")
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The analytic leverages Azure Active Directory AuditLogs for the "Update user" operation and compares the UserType modifiedProperty old and new values.
  mitigation_plan:
    - priority: medium
      action: Implement periodic access reviews for all guest accounts to ensure their current permissions and UserType status remain appropriate for their business function.
      owner: Identity Team
      addresses: T1098
updates:
  - at: "2026-11-03T15:16:44Z"
    level: L1
    summary: added coverage for Microsoft Entra ID
    sources:
      - splunk-escu
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/cloud/azure_ad_guest_user_type_changed_to_member.yml
---

This threat brief describes a detection pattern for unauthorized Microsoft Graph API usage. It correlates non-interactive Microsoft Entra ID sign-ins (asserting managed, Azure AD joined device context and an Edge user agent) with subsequent activity where the exact access token is used by a scripted client to query at least three distinct directory-enumeration paths in Microsoft Graph. This approach utilizes the unique token identifier to correlate activity, rather than relying on session identifiers.
