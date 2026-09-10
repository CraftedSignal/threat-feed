---
title: Entra ID Windows Hello for Business Credential Registration Persistence
slug: 2026-09-entra-id-whfb-persistence
description: Adversaries can establish durable, phishing-resistant persistence in Microsoft Entra ID by registering unauthorized Windows Hello for Business (WHfB) credentials to survive password resets and session revocations.
date: "2026-09-10T18:47:58Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - cloud-security
  - entra-id
  - identity-and-access
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries who have obtained a token that satisfies fresh (NGC) multi-factor authentication... can also enroll their own WHfB credential to establish durable, phishing-resistant persistence.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_id_whfb_credential_registration.toml
  - https://dirkjanm.io/borrowing-windows-hello-keys/
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Implement monitoring for 'Add Windows Hello for Business credential' operations in Azure Audit Logs
      owner: Detection Engineering
      due: 72h
      evidence: Source provides specific logic for flagging first-seen enrollments.
  hunt_leads:
    - lead: Identify WHfB registrations from ASNs not previously associated with a user in the last 14 days
      technique_id: T1098.001
      data_needed:
        - Azure Audit Logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Rule uses 'new_terms' logic over a 14-day window.
---

This threat involves the abuse of the Windows Hello for Business (WHfB) credential registration process within Microsoft Entra ID. While WHfB is a standard onboarding and passwordless authentication feature, it can be repurposed by adversaries for persistent access. Attackers who have successfully compromised a valid user account, specifically one with existing WHfB or passkey access, can leverage that access to satisfy multi-factor authentication (MFA) requirements for registering a new, attacker-controlled credential. This credential becomes a permanent fixture of the account, remaining valid even if the user resets their password or if existing browser sessions are revoked. This technique provides a robust mechanism for long-term access that is resistant to standard remediation efforts, necessitating careful monitoring of new credential registration patterns across a tenant.

## Impact

Successful exploitation allows an adversary to maintain long-term, persistent access to a compromised account within the target's Entra ID environment. Because the registered credential is device-bound and satisfies MFA requirements, the persistence survives common incident response actions such as password resets and session token invalidation. This poses a high risk for continued unauthorized access, data exfiltration, and lateral movement within the cloud identity perimeter.

## Recommendation

- Deploy detection logic to identify first-seen WHfB credential registrations correlated with new or anomalous source Autonomous System Numbers (ASN) within the tenant environment.
- Review the sign-in history immediately preceding any detected WHfB registration for signs of deviceless authentication, device-code flow abuse, or anomalous geographic activity.
- If unauthorized registration is confirmed, delete the malicious WHfB credential via the Entra portal or Microsoft Graph API, revoke all active sessions, and force a credential re-enrollment from a trusted, physical device.
