---
brief_id: brief-2026-09-entra-id-prt-replay
event_id: brief-2026-09-entra-id-prt-replay
revision: 2
activity_at: "2026-11-03T21:43:45Z"
revision_history:
  - revision: 2
    at: "2026-11-03T21:43:45Z"
    checksum: sha256:b451073f6abf50a9db0aeddf1f5ea1565bca0de553834b00dd5548e43d800280
    summary: exploited:true
    changed_fields:
      - affected_products
      - claim_state
      - exploitation_evidence
      - lastmod
      - references
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_entra_id_prt_cookie_replay_unusual_ip.toml
title: Entra ID Device-Bound PRT Replay via First-Party Apps
slug: 2026-09-entra-id-prt-replay
description: Adversaries are leveraging stolen Primary Refresh Tokens (PRTs) to perform off-box authentication against Microsoft 365 services by masquerading as first-party FOCI clients from unauthorized IP addresses.
date: "2026-09-23T01:17:34Z"
lastmod: "2026-11-03T21:42:52Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_entra_id_prt_cookie_replay_unusual_ip.toml
  observed_at: "2026-11-03T17:51:54Z"
  confidence: high
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against source intelligence
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
  - Entra ID
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.001
    subtechnique_name: Application Access Token
    evidence: Adversaries may steal a Primary Refresh Token (PRT) from a Windows workstation and replay it from an external, unauthorized IP address using first-party FOCI (Family of Client IDs) applications.
    confidence_band: high
references:
  - https://www.armadin.com/blog-posts/prtremote-extract-prt-cookies-remotely-with-interactivetoken-scheduled-task
  - https://github.com/armadin-public/PRTremote
  - https://github.com/dmcxblue/ANIMO/blob/master/helpers/scripts/GrabTokenAzureAD/PrtExtractor.cs
  - https://github.com/rvrsh3ll/TokenTactics
  - https://github.com/Gerenios/AADInternals
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_entra_id_prt_cookie_replay_unusual_ip.toml
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
updates:
  - at: "2026-11-03T21:42:52Z"
    level: L3
    summary: exploited:true
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_entra_id_prt_cookie_replay_unusual_ip.toml
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
