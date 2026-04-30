---
title: Okta Group Membership Spike Detection
slug: 2024-01-okta-group-spike
description: A machine learning job has identified an unusual spike in Okta group membership events, indicating potential privileged access activity where attackers or malicious insiders might be adding accounts to privileged groups to escalate their access, potentially leading to unauthorized actions or data breaches.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - privileged-access
  - privilege-escalation
  - okta
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/pad
rules:
  - title: Okta - Spike in Group Membership Changes
    description: Detects a spike in Okta group membership changes, potentially indicating malicious privilege escalation activity.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - okta
  - title: Okta - Account Added to Privileged Group
    description: Detects when an account is added to a group with high privileges.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - okta
rules_count: 2
---

This rule leverages machine learning to detect unusual spikes in Okta group membership events, potentially indicating privileged access activity. The detection logic is based on the "pad_okta_spike_in_group_membership_changes_ea" machine learning job. The rule aims to identify scenarios where attackers or malicious insiders are adding accounts to privileged groups within Okta to escalate their privileges, which could lead to unauthorized actions and data breaches. This rule requires the Privileged Access Detection integration assets to be installed, as well as Okta logs collected by integrations such as Okta. The rule's anomaly threshold is set to 75, and it analyzes data from the last 3 hours at 15-minute intervals.

## Attack Chain

1. An attacker gains initial access to an Okta account, potentially through compromised credentials or phishing.
2. The attacker uses the compromised account to access the Okta admin interface.
3. The attacker identifies high-privilege groups within Okta, such as those with access to sensitive applications or data.
4. The attacker adds their controlled account or a compromised user account to one or more of these privileged groups.
5. Okta logs the group membership change event.
6. The machine learning job "pad_okta_spike_in_group_membership_changes_ea" detects an unusual spike in these group membership events.
7. The detection rule triggers, alerting security personnel to the potential privilege escalation.
8. The attacker leverages the newly acquired privileges to access sensitive resources or perform unauthorized actions.

## Impact

A successful privilege escalation attack in Okta can lead to significant damage. Attackers can gain access to sensitive applications and data, compromise other user accounts, and potentially disrupt business operations. The number of affected users and the scope of the damage depend on the privileges associated with the compromised groups. Detecting and responding to these spikes is crucial to preventing widespread data breaches and maintaining the integrity of the Okta environment.

## Recommendation

*   Ensure the Privileged Access Detection integration is installed and configured correctly, including the "pad_okta_spike_in_group_membership_changes_ea" machine learning job, as outlined in the [setup instructions](#setup).
*   Review the specific Okta group membership events that triggered the alert to identify which accounts were added to privileged groups, as suggested in the [investigation guide](#triage-and-analysis).
*   Implement additional monitoring on affected accounts and privileged groups to detect any further suspicious activity, following the [response and remediation steps](#response-and-remediation).
*   Create exceptions for routine administrative tasks or automated scripts that legitimately manage group memberships to reduce false positives, as detailed in the [false positive analysis](#false-positive-analysis).
