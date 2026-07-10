---
title: Cisco Duo Policy Bypass via 2FA Disablement
slug: 2024-01-cisco-duo-policy-bypass
description: An attacker modifies Cisco Duo policies to allow access without two-factor authentication (2FA), potentially gaining unauthorized access to systems and data.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cisco-duo
  - 2fa-bypass
  - policy-modification
vendors:
  - Cisco
products:
  - Duo
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://splunkbase.splunk.com/app/7404
rules:
  - title: Cisco Duo Policy Created Allowing 2FA Bypass
    description: Detects when a Cisco Duo policy is created to allow access without 2FA.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1556
    data_sources:
      - authentication
      - cisco_duo
  - title: Cisco Duo Policy Updated Allowing 2FA Bypass
    description: Detects when a Cisco Duo policy is updated to allow access without 2FA.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1556
    data_sources:
      - authentication
      - cisco_duo
rules_count: 2
---

This threat involves the modification of Cisco Duo policies to disable or bypass two-factor authentication (2FA). The attack leverages administrative access, either legitimate or compromised, to alter the Duo configuration. This manipulation allows unauthorized access to systems and applications normally protected by 2FA. This activity is identified by analyzing Cisco Duo administrator activity logs for policy changes that set the authentication status to "Allow access without 2FA". This is a critical issue because it significantly weakens the security posture of an organization, potentially leading to widespread compromise.

## Attack Chain

1.  The attacker gains access to a Cisco Duo administrator account, either through credential theft, social engineering, or exploiting a vulnerability.
2.  The attacker logs into the Cisco Duo Admin Panel.
3.  The attacker navigates to the "Policies" section within the Duo Admin Panel.
4.  The attacker identifies a target policy to modify or creates a new policy.
5.  The attacker modifies the policy settings, specifically changing the "Authentication Status" to "Allow access without 2FA."
6.  The attacker saves the modified policy.
7.  Users covered by the modified policy can now access protected applications and systems without completing 2FA.
8.  The attacker exploits the lack of 2FA to gain unauthorized access to sensitive systems and data, potentially leading to data exfiltration, system compromise, or further lateral movement.

## Impact

Successful exploitation allows attackers to bypass two-factor authentication, a critical security control. This can lead to unauthorized access to sensitive systems and data, potentially resulting in data breaches, financial loss, and reputational damage. The impact is widespread as any application or system protected by the affected Duo policy becomes vulnerable. The damage can be extensive, depending on the scope of access granted by the bypassed 2FA.

## Recommendation

*   Deploy the Sigma rule `Cisco Duo Policy Created Allowing 2FA Bypass` to detect the creation of policies bypassing 2FA and tune for your environment.
*   Deploy the Sigma rule `Cisco Duo Policy Updated Allowing 2FA Bypass` to detect modifications of existing policies bypassing 2FA and tune for your environment.
*   Monitor Cisco Duo administrator activity logs for unauthorized or suspicious policy changes as described in the "Overview" section.
*   Review and enforce strong access controls for Cisco Duo administrator accounts, including multi-factor authentication, as this is the initial access vector.
*   Install the Cisco Security Cloud App from Splunkbase (https://splunkbase.splunk.com/app/7404) to ensure proper data ingestion from Cisco Duo.
