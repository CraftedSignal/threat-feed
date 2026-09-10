---
title: Entra ID Windows Hello for Business and Passkey Key Borrowing
slug: 2026-09-entra-whfb-borrowing
description: Adversaries are exploiting the 'Windows Hello key borrowing' technique by replaying device-bound credentials from unauthorized infrastructure to authenticate against Entra ID, facilitating session hijacking and device registration.
date: "2026-09-10T18:47:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - entra-id
  - defense-evasion
  - initial-access
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: A same-tenant sign-in with an empty device_detail.device_id means the key material is being used away from its bound device - the core signal of the 'borrowing Windows Hello keys' technique.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This is the core primitive of the 'borrowing Windows Hello keys' technique and is a strong precursor to attacker device registration and Primary Refresh Token (PRT) issuance.
    confidence_band: high
references:
  - https://dirkjanm.io/borrowing-windows-hello-keys/
  - https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/defense_evasion_entra_id_whfb_key_from_unregistered_device.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity Team
  immediate_actions:
    - action: Deploy detection for successful passwordless sign-ins without device_id
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific KQL query logic for Entra ID logs.
  hunt_leads:
    - lead: Audit Entra ID logs for sign-ins where authentication_method is WHfB/FIDO2/passkey and device_id is empty or missing.
      technique_id: T1550
      data_needed:
        - Azure Sign-in Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as the core primitive of the technique.
---

Adversaries are utilizing a sophisticated technique known as "Windows Hello key borrowing" to circumvent phishing-resistant authentication in Microsoft Entra ID. Because Windows Hello for Business (WHfB), FIDO2 security keys, and passkeys are cryptographically bound to a device's Trusted Platform Module (TPM), a legitimate authentication should always be associated with a registered device identifier. Attackers bypass this by extracting the key material or signing assertions offline and replaying them from attacker-controlled infrastructure. This manifests in Entra ID sign-in logs as a successful authentication using a phishing-resistant method, but with an empty or missing `device_detail.device_id`. This technique allows an attacker to mint device-agnostic tokens or perform unauthorized device registration, effectively moving from credential theft to full device-bound Primary Refresh Token (PRT) compromise without ever possessing the physical hardware.

## Attack Chain

1. Attacker performs initial reconnaissance to identify a target user and gain access to their local system, potentially via prior malware infection.
2. Attacker exfiltrates the TPM-bound credential material or leverages existing access to sign authentication assertions using the target's identity.
3. Attacker uses a tool (e.g., roadtx) to perform an authentication request against Entra ID from their own VPS or controlled infrastructure.
4. The request utilizes the stolen WHfB/FIDO2 assertion to satisfy MFA requirements.
5. The Entra ID authentication log records a success, but the `device_detail.device_id` field is null or empty, reflecting that the sign-in did not originate from the registered device.
6. Attacker leverages the authenticated session to register a new rogue device or mint device-agnostic tokens.
7. Attacker gains persistent access to corporate resources, bypassing traditional Conditional Access policies that require managed or compliant devices.

## Impact

Successful exploitation allows attackers to gain unauthorized access to an identity without the physical device, potentially leading to widespread session hijacking, persistent access through rogue device registration, and the bypass of phishing-resistant MFA controls. This technique is specifically targeted at enterprise cloud environments relying on Entra ID for identity and access management.

## Recommendation

Prioritize the identification of "borrowing" attempts and enforce stricter device compliance.

- Deploy the provided detection logic to monitor for successful Entra ID sign-ins using passwordless methods that lack an associated `device_id`.
- Investigate any hits by reviewing the `source.ip`, `user_agent.original`, and subsequent `azure.auditlogs` for unauthorized device registrations or credential additions.
- Revoke refresh tokens and delete any unrecognized devices immediately if a "borrowing" attempt is confirmed.
- Implement Conditional Access policies requiring device compliance for all sensitive resources, which acts as a secondary defense if an attacker attempts to use a rogue device.
