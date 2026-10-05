---
title: Detection of Privileged Role Assignment to Azure Service Principals
slug: 2026-10-o365-spn-priv-esc
description: This brief details the detection of potential privilege escalation in Azure Active Directory where attackers assign highly privileged roles to service principals to maintain persistent, elevated cloud access.
date: "2026-10-05T12:08:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: The following analytic detects potential privilege escalation threats in Azure Active Directory (AD) by identifying instances where privileged roles are assigned to service principals.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1098/003/
  - https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review existing O365 audit logging to ensure 'Add member to role' events are ingested.
      owner: Detection Engineering
      due: 48h
      evidence: Source requirement for O365 Universal Audit Log ingestion.
  hunt_leads:
    - lead: Identify all service principals currently assigned roles with Global Administrator or equivalent privileges.
      technique_id: T1098.003
      data_needed:
        - Azure AD/Entra ID Role Assignment logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Service principals with high privileges provide a mechanism for persistence.
  mitigation_plan:
    - priority: immediate
      action: Review and remove unnecessary privileged role assignments from service principals.
      owner: IT Operations
      addresses: T1098.003
      evidence: Least privilege access control reduces the impact of service principal compromise.
---

Adversaries targeting Azure Active Directory (now Microsoft Entra ID) environments often seek to establish persistence and escalate privileges by manipulating service principals. By assigning high-privilege roles to a compromised or attacker-controlled service principal, an actor can leverage the non-human identity to perform actions, exfiltrate data, or further compromise the cloud tenant without the need for interactive user credentials. This activity is a common technique used by groups like Lapsus$ to achieve long-term access. Detection requires monitoring O365 Universal Audit Logs for role assignment operations (e.g., 'Add member to role') where the target identity is a service principal rather than a standard user account. Defenders should correlate these assignments against a list of known privileged role templates to filter for critical escalation risks.

## Attack Chain

1. Attacker gains initial access to an Azure environment, potentially through a compromised user account with permission to modify identity configurations.
2. Attacker discovers an existing service principal or creates a new one to serve as a backdoored identity.
3. Attacker identifies a target privileged role in Azure AD (e.g., Global Administrator or Privileged Role Administrator).
4. Attacker performs an 'Add member to role' operation via the Azure portal, CLI, or API, targeting the service principal identity.
5. The O365 Universal Audit Log records the role assignment event including the Actor (initiator) and the ObjectId (target).
6. The service principal assumes the new permissions, allowing the attacker to interact with cloud resources or Microsoft Graph API with elevated rights.
7. Attacker uses the service principal to maintain persistence, bypassing conditional access policies or password rotation requirements associated with human users.

## Impact

Successful exploitation allows attackers to gain full administrative control over an Azure tenant, facilitating data exfiltration, shadow administrator creation, and total compromise of managed cloud resources. This impact is significant for organizations relying on Azure for identity and infrastructure management.

## Recommendation

Deploy detection logic to alert on role assignment operations targeting non-human entities.
- Implement a monitoring pipeline for O365 Universal Audit Log events using the 'Add member to role' and 'Add eligible member to role' operations.
- Maintain an up-to-date lookup table of 'privileged_azure_ad_roles' to compare against the 'object_id' reported in the audit logs.
- Prioritize alerts where the Target category is 'ServicePrincipal' to filter out standard user modifications.
- Use the provided drilldown searches in your SIEM to investigate the full scope of activity associated with the 'src_user' and 'user' identified in the event.
