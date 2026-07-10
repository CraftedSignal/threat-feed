---
title: Cisco Duo Policy Allowing Tampered Devices
slug: 2024-01-03-cisco-duo-tampered-devices
description: A threat actor modifies or creates a Cisco Duo policy to allow tampered or rooted devices to access protected resources, potentially bypassing security controls and enabling unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cisco_duo
  - policy_change
  - tampered_devices
  - rooted_devices
  - identity
vendors:
  - Cisco
products:
  - Duo
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://splunkbase.splunk.com/app/7404
rules:
  - title: Cisco Duo Policy Allowing Tampered Devices
    description: Detects when a Cisco Duo policy is created or updated to allow rooted devices to access protected resources.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1556
    data_sources:
      - webserver
      - linux
  - title: Cisco Duo Policy Allowing Tampered Devices (Logs)
    description: Detects when a Cisco Duo policy is created or updated to allow rooted devices to access protected resources, based on administrator logs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1556
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This analytic detects when a Duo policy is created or updated to allow tampered or rooted devices (e.g., jailbroken smartphones) to access protected resources. The detection focuses on changes to Duo policies where the `allow_rooted_devices` setting is enabled. The activity is identified through the examination of Cisco Duo administrator activity logs. This poses a significant security risk because tampered devices can bypass security controls, run unauthorized software, and become more susceptible to compromise. The ability to modify these settings can be indicative of a misconfiguration or a malicious attempt to weaken authentication requirements, potentially granting attackers access to sensitive systems using compromised devices.

## Attack Chain

1. An attacker gains access to an administrative account within the Cisco Duo environment.
2. The attacker authenticates to the Duo Admin Panel.
3. The attacker navigates to the Policies section within the Duo Admin Panel.
4. The attacker modifies an existing policy or creates a new policy.
5. During policy creation or modification, the attacker enables the "Allow rooted devices" setting, which is represented as `allow_rooted_devices=true` in the policy description.
6. The Duo Admin Panel logs the policy creation or update event in the administrator activity logs.
7. Tampered devices are now able to authenticate via Duo and access protected resources.

## Impact

A successful attack can lead to the circumvention of security controls on tampered devices, unauthorized access to sensitive systems, data breaches, and potential lateral movement within the network. Organizations relying on Duo for multi-factor authentication may experience a significant degradation in their security posture if this policy is enabled, potentially affecting thousands of users and devices.

## Recommendation

*   Deploy the Sigma rule `Cisco Duo Policy Allowing Tampered Devices` to detect the creation or modification of Duo policies allowing tampered devices by monitoring the Duo administrator activity logs.
*   Review and audit existing Duo policies to identify any unintentional or malicious configurations allowing tampered devices.
*   Monitor the `Cisco Duo Administrator` logs for suspicious activity, especially related to policy changes.
*   Investigate any alerts triggered by the Sigma rule and remediate by reverting the policy change.
