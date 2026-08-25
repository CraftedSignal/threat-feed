---
title: Detection of Anomalous Entra ID Authentication Methods
slug: 2026-08-entra-id-unusual-auth
description: Adversaries may use stolen credentials with unusual authentication methods to bypass Conditional Access Policies and MFA in Microsoft Entra ID environments.
date: "2026-08-25T18:44:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - identity
  - cloud
  - entra-id
  - authentication
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An adversary with stolen credentials may attempt to authenticate with an unusual method, which may indicate an attempt to bypass conditional access policies (CAP) and multi-factor authentication (MFA) requirements.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: An adversary with stolen credentials may attempt to authenticate with an unusual method, which may indicate an attempt to bypass conditional access policies (CAP) and multi-factor authentication (MFA) requirements.
    confidence_band: high
rules:
  - title: Entra ID User Sign-in with Unusual Authentication Type
    description: Identifies rare authentication methods used by Entra ID members that bypass MFA, potentially indicating credential abuse.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy new terms detection for Entra ID authentication methods.
      owner: Detection Engineering
      due: 72h
      evidence: Source detection rule provided.
  hunt_leads:
    - lead: Search for rare authentication methods in sign-in logs over the last 30 days.
      technique_id: T1078.004
      data_needed:
        - Azure Sign-in Logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Rule focuses on first occurrences in 14 days; wider lookback may identify historical outliers.
---

This detection brief addresses the risk of adversaries leveraging stolen credentials to authenticate to Microsoft Entra ID using non-standard or previously unseen authentication methods. By utilizing authentication flows that diverge from a user's historical baseline, attackers attempt to bypass Conditional Access Policies (CAP) and multi-factor authentication (MFA) requirements. 

This technique is significant for defenders because it targets the gap between standard user behavior and the configuration of authentication requirements. The detection focuses on successful sign-in events where the authentication method has not been recorded for a specific user within the previous 14 days, particularly in environments where MFA was not triggered. Organizations should investigate these events to distinguish between legitimate user onboarding or policy changes and malicious attempts to circumvent identity security controls.

## Impact

Successful exploitation of this technique allows adversaries to establish unauthorized access to cloud resources using valid identities. This bypasses security mechanisms intended to verify user identity, potentially leading to unauthorized data exfiltration, persistent access, and compromise of sensitive cloud assets. The scale of impact is dependent on the privileges assigned to the compromised account and the effectiveness of secondary monitoring controls.

## Recommendation

* Deploy the provided detection logic to identify the first occurrence of unusual authentication methods for Entra ID users.
* Investigate alerts by verifying the `source.ip` against known malicious infrastructure and reviewing the user's recent sign-in history.
* Verify if the authentication protocol recorded in `azure.signinlogs.properties.authentication_protocol` aligns with expected business applications.
* Ensure MFA is enforced via Conditional Access Policies for all users, particularly those with high-privileged roles.
* Restrict the use of legacy authentication protocols that do not support modern MFA requirements.
