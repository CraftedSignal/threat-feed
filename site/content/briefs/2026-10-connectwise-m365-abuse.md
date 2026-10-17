---
title: Unauthorized Access via Compromised ConnectWise M365 Vendor Credentials
slug: 2026-10-connectwise-m365-abuse
description: Threat actors are leveraging compromised API secrets from ConnectWise Cloud Backup and MS Teams integration applications to gain unauthorized administrative access and establish persistence in Microsoft 365 environments.
date: "2026-10-17T10:28:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cloud-security
  - supply-chain
  - m365
  - identity-compromise
vendors:
  - Microsoft
  - ConnectWise
products:
  - Microsoft 365
  - ConnectWise Cloud Backup (<= 2026-10-16)
  - ConnectWise Cloud Management - MS Teams (<= 2026-10-16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The attacker authenticates to the app using their own tooling, the same way the backup service does, and gets tokens with the app's existing permissions.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136
    technique_name: Create Account
    evidence: a second ConnectWise application... gave itself Global Administrator and then added new credentials to two other applications in that tenant
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: The actor moved through tenants in sorted GUID order, a few seconds apart, which points to a script working from a target list.
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
    - action: Disable ConnectWise Cloud Backup (506e08f9-6e9a-4da4-942b-a099a03644ae) and ConnectWise Cloud Management - MS Teams (24205314-2b89-4e07-a2a4-579e898a5640) applications.
      owner: IAM Team
      due: immediate
      evidence: Impacted organizations should immediately disable the ConnectWise Cloud Backup... and ConnectWise Cloud Management - MS Teams applications
  hunt_leads:
    - lead: Search Entra ID logs for sign-ins from 144.172.64.128.
      technique_id: T1078.004
      data_needed:
        - Azure AD Sign-in Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The credential type was a client assertion... used to obtain Microsoft Graph tokens... from 144.172.64[.]128
  mitigation_plan:
    - priority: immediate
      action: Remove unauthorized application credentials and reset secrets for impacted applications.
      owner: IAM Team
      addresses: Persistence via application credentials
      evidence: You must review the credentials on all of your M365 applications.
---

Threat actors have obtained API secret credentials for ConnectWise Cloud Backup (formerly SkyKick) and ConnectWise Cloud Management - MS Teams applications. These credentials allow attackers to impersonate these legitimate service provider applications to authenticate into customer Microsoft 365 tenants. Because these applications are granted broad permissions to interact with Exchange, OneDrive, SharePoint, and Entra ID data, the compromise provides attackers with extensive read/write access. Observed activity beginning October 15, 2026, involves automated scripts iterating through target tenants to request Microsoft Graph tokens. Attackers have been observed using these elevated permissions to grant themselves Global Administrator roles and add malicious credentials to other applications within the target tenant, creating a persistent backdoor independent of the initial compromised integration.

## Attack Chain

1. Attackers obtain valid API client assertions for ConnectWise service applications via a breach of the vendor infrastructure.
2. Attackers perform automated authentication to customer Microsoft 365 tenants using the compromised application identities from a hosting provider IP (144.172.64.128).
3. Attackers acquire Microsoft Graph API tokens with the permissions historically consented to the ConnectWise applications.
4. Attackers leverage the compromised app's directory permissions to escalate their privilege level to Global Administrator.
5. Attackers create new credentials for existing, unrelated applications within the tenant to ensure long-term persistence.
6. Attackers potentially exfiltrate sensitive data from mailboxes, OneDrive, and SharePoint repositories.

## Impact

At least 162 M365 tenants have been confirmed compromised as of October 16, 2026. The compromise allows attackers to read and potentially exfiltrate sensitive directory, email, and document data. The establishment of persistence via new application credentials means that even if the initial ConnectWise integration is disabled, the attacker maintains unauthorized access until the newly added fraudulent credentials are removed.

## Recommendation

1. Immediately disable the affected ConnectWise applications (App IDs: 506e08f9-6e9a-4da4-942b-a099a03644ae and 24205314-2b89-4e07-a2a4-579e898a5640) in your Microsoft 365 environment.
2. Perform a comprehensive audit of all applications in the Entra ID portal to identify and remove any unauthorized credentials added recently.
3. Review Microsoft Entra sign-in logs for any API-based authentication attempts originating from the identified malicious IP 144.172.64.128.
4. Ensure all newly added credentials for high-privilege applications are thoroughly vetted and approved by internal security teams.
