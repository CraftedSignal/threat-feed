---
title: Entra ID Device-Bound PRT Replay via First-Party Apps
slug: 2026-09-entra-id-prt-replay
description: Adversaries are leveraging stolen Primary Refresh Tokens (PRTs) to perform off-box authentication against Microsoft 365 services by masquerading as first-party FOCI clients from unauthorized IP addresses.
date: "2026-09-23T01:17:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - defense-evasion
  - cloud
  - identity
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft Graph
  - SharePoint Online
  - OneDrive for Business
  - Exchange Online
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Adversaries may steal a Primary Refresh Token (PRT) from a Windows workstation and replay it from an external, unauthorized IP address using first-party FOCI (Family of Client IDs) applications.
    confidence_band: high
references:
  - https://www.armadin.com/blog-posts/prtremote-extract-prt-cookies-remotely-with-interactivetoken-scheduled-task
  - https://github.com/armadin-public/PRTremote
  - https://github.com/dmcxblue/ANIMO/blob/master/helpers/scripts/GrabTokenAzureAD/PrtExtractor.cs
  - https://github.com/rvrsh3ll/TokenTactics
  - https://github.com/Gerenios/AADInternals
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy ES|QL detection logic for anomalous PRT replay
      owner: Detection Engineering
      due: 48h
      evidence: Source detection rule requirement
  hunt_leads:
    - lead: Check Azure Sign-in logs for PRT redemption from non-workstation IPs
      technique_id: T1550.001
      data_needed:
        - SignInLogs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source investigation guide
  mitigation_plan:
    - priority: immediate
      action: Revoke refresh tokens for identified accounts
      owner: SOC
      addresses: Credential theft recovery
      evidence: Source response section
---

Adversaries are increasingly exploiting the trust model of Entra ID device-bound Primary Refresh Tokens (PRTs) to gain unauthorized access to Microsoft Graph, SharePoint, OneDrive, and Exchange Online. By harvesting a PRT cookie from a compromised Windows workstation, attackers can perform an off-box authentication replay using first-party FOCI (Family of Client IDs) applications such as Azure CLI, Azure PowerShell, or VS Code. Because the stolen PRT retains the device ID of the original, compliant workstation, this technique successfully bypasses Conditional Access policies that require a managed or compliant device, even when the connection originates from an untrusted IP address. This threat is particularly dangerous as it misuses legitimate administrative tooling to access high-value cloud resources, often leaving minimal footprint within traditional network-based monitoring. Organizations must differentiate between legitimate on-box activity and anomalous off-box token redemption to identify active compromises.

## Attack Chain

1. Attacker establishes persistence or code execution on the target Windows workstation using administrative privileges.
2. Attacker utilizes custom tooling (e.g., PRTremote, TokenTactics, or AADInternals) to interact with the Windows Authentication Broker (WAM) or extract stored PRT cookies.
3. Attacker exfiltrates the PRT cookie and associated device-bound metadata, such as the `deviceid` and nonce, to an external C2 infrastructure.
4. Attacker initiates an authentication request to Entra ID using a first-party client ID (e.g., Azure CLI `04b07795-8ddb-461a-bbee-02f9e1bf7b46`).
5. The Entra ID service validates the request, seeing a valid PRT associated with a compliant or Intune-managed device ID.
6. Conditional Access policies evaluate the request as originating from a compliant device, granting the attacker a session token.
7. Attacker uses the granted access token to interact with Microsoft Graph, SharePoint, or Exchange Online to exfiltrate data or enumerate directory objects.

## Impact

Successful exploitation allows attackers to gain authenticated access to sensitive cloud environments while evading device-based security controls. This can result in unauthorized data exfiltration from SharePoint and OneDrive, access to enterprise mailboxes, and potential reconnaissance of the entire Microsoft 365 tenant directory. Because the tokens are tied to legitimate compliant devices, traditional IP-based filtering or device compliance checks are rendered ineffective, enabling long-lived access within the five-minute valid window of the PRT cookie nonce.

## Recommendation

1. Deploy the provided ES|QL detection query to monitor for PRT replay events from first-party FOCI clients that originate from IPs not associated with the legitimate user's device sign-in history.
2. Validate anomalous sign-in events by verifying if the Graph client activity correlates with the workstation's expected egress IP.
3. Implement conditional access logging to specifically track `primaryRefreshToken` redemption attempts that present `is_compliant` or `is_managed` status.
4. In the event of a confirmed compromise, initiate a global revocation of refresh tokens and PRTs for the affected user identity.
5. Investigate endpoints for the presence of token-harvesting artifacts such as `BrowserCore.exe` execution, scheduled tasks, or temporary files containing nonce strings.
