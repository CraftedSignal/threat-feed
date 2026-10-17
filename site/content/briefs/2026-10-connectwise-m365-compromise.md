---
title: Unauthorized Access to Microsoft 365 Tenants via Compromised ConnectWise Credentials
slug: 2026-10-connectwise-m365-compromise
description: Threat actors are exploiting a compromised service principal credential belonging to ConnectWise Cloud Backup to gain unauthorized access to 173 Microsoft 365 tenants and potentially escalate privileges.
date: "2026-10-17T06:39:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - supply-chain
  - identity-theft
  - m365
vendors:
  - ConnectWise
  - Microsoft
products:
  - ConnectWise Cloud Backup (formerly SkyKick)
  - ConnectWise Cloud Management app for Microsoft Teams
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078.004
    technique_name: 'Valid Accounts: Cloud Accounts'
    evidence: The adversary has been observed authenticating to the app using their own tooling, in a manner analogous to the backup service.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098.002
    technique_name: 'Account Manipulation: Additional Cloud Credentials'
    evidence: Adding a credential to an MSP management application can extend access beyond the one tenant.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.003
    technique_name: 'Create Account: Cloud Account'
    evidence: The ConnectWise Cloud Management app added itself to the Global Administrator role.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: It was used to obtain Microsoft Graph tokens in customer tenants.
    confidence_band: high
iocs:
  - type: ip
    value: 144.172.64.128
ioc_counts:
  ip: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IAM Team
  immediate_actions:
    - action: Disable ConnectWise Cloud Backup and Cloud Management apps in Entra ID
      owner: IAM Team
      due: 2h
      evidence: ConnectWise has taken the step of closing Cloud Backup application access until further notice.
    - action: Block IP 144.172.64.128
      owner: Network Security
      due: 1h
      evidence: 'Suspicious IP address: 144.172.64[.]128'
  hunt_leads:
    - lead: Search Entra audit logs for App ID 24205314-2b89-4e07-a2a4-579e898a5640 adding secrets
      technique_id: T1098.002
      data_needed:
        - Entra audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The ConnectWise Cloud Management app added itself to the Global Administrator role, then ran a Python script that modified two other applications
  mitigation_plan:
    - priority: immediate
      action: Revoke sessions and rotate secrets for applications modified by the compromised principal
      owner: IAM Team
      addresses: Account Manipulation
      evidence: Adding a credential to an MSP management application can extend access
---

Security researchers have identified an active campaign where unknown threat actors are leveraging a compromised Microsoft 365 (M365) service principal credential associated with ConnectWise Cloud Backup (formerly SkyKick) to access customer environments. The compromised application holds extensive permissions to mailboxes, OneDrive, SharePoint, Teams, and directory data. The attackers have been observed moving through impacted tenants in a scripted manner, obtaining Microsoft Graph tokens to facilitate unauthorized data access. 

In addition to direct data access, the threat actors have demonstrated the ability to escalate privileges within affected tenants by modifying application configurations and adding new client secrets to other highly privileged MSP management and security applications. This activity effectively persists the actor's presence and expands their reach across the MSP's downstream client base. ConnectWise has temporarily suspended application access while investigating the breach. Defenders should prioritize auditing Entra ID sign-in and audit logs for the specified application IDs and unauthorized activities occurring from known attacker infrastructure.

## Attack Chain

1. Attacker gains access to the ConnectWise Cloud Backup service principal credential via an undisclosed method.
2. Actor authenticates to Microsoft Graph as the compromised ConnectWise Cloud Backup application using the stolen credential.
3. Attacker uses the app's inherited permissions to access sensitive organizational data, including Exchange mailboxes, SharePoint, and OneDrive files.
4. Actor interacts with Entra ID to assign the application Global Administrator privileges.
5. Actor uses the application context to identify other trusted, privileged MSP or security management applications installed in the tenant.
6. Actor executes scripts (observed using Python-urllib/3.12 user-agent) to add new client secrets to these trusted applications.
7. Actor leverages the new client secrets to facilitate long-term persistence and facilitate movement into other downstream customer tenants.

## Impact

At least 173 Microsoft 365 customer tenants have been confirmed as compromised. The attack allows for unauthorized access to sensitive mailboxes, SharePoint/OneDrive files, and directory data. Furthermore, the ability to inject credentials into security and MSP management tools creates a high risk of supply chain contamination, potentially allowing the attacker to pivot from a single compromised tenant into the MSP's entire client base.

## Recommendation

* Disable the ConnectWise Cloud Backup (App ID: 506e08f9-6e9a-4da4-942b-a099a03644ae) and ConnectWise Cloud Management app (App ID: 24205314-2b89-4e07-a2a4-579e898a5640) in your Entra ID environment until confirmed safe by the vendor.
* Audit Entra audit logs for any unauthorized modification of application credentials or role assignments involving the specified App IDs since October 13, 2026.
* Block the IP address 144.172.64.128 at the network perimeter or within cloud conditional access policies as it has been identified as a source of malicious authentication activity.
* Enable and review Microsoft Graph activity logs for abnormal data access patterns or unauthorized token requests.
* Perform a credential rotation for all MSP and security-related applications that may have been accessed or modified by the ConnectWise service principal.
