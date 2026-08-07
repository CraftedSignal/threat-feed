---
title: Account Takeover Vulnerability in TrueBooker WordPress Plugin
slug: 2026-08-truebooker-ato
description: An unauthenticated account takeover vulnerability (CVE-2026-14364) in the TrueBooker plugin allows attackers to reset arbitrary user passwords due to missing identity validation.
date: "2026-08-07T05:30:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - vulnerability
  - account-takeover
vendors:
  - themetechmount
products:
  - TrueBooker – Appointment Booking and Scheduler System (1.2.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: The TrueBooker – Appointment Booking and Scheduler System plugin for WordPress is vulnerable to account takeover via improper password reset validation.
    confidence_band: high
cves:
  - id: CVE-2026-14364
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14364
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/f441477e-35b8-42ae-b71c-3fdba126021b?source=cve
  - https://plugins.trac.wordpress.org/changeset/3595807/truebooker-appointment-booking
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update TrueBooker plugin to a version above 1.2.3.
      owner: IT Operations
      due: 24h
      evidence: Plugin version 1.2.3 and below are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Identify and disable vulnerable TrueBooker plugin until patched.
      owner: IT Operations
      addresses: CVE-2026-14364
      evidence: Account takeover vulnerability.
---

The TrueBooker - Appointment Booking and Scheduler System plugin for WordPress (versions 1.2.3 and below) contains a critical security flaw categorized as CWE-640: Weak Password Recovery Mechanism for Forgotten Password. The vulnerability stems from the plugin's failure to properly validate a user's identity during the password reset workflow. Because the identity check is absent, an unauthenticated attacker can supply a target user's identifier - such as an administrator account - to the password reset endpoint, triggering a password change or reset without authorization. This allows for full account takeover and subsequent persistent access to the WordPress environment. Given the critical CVSS 3.1 score of 9.8, this vulnerability poses a severe risk to any organization utilizing the plugin for scheduling services.

## Attack Chain

1. Attacker performs reconnaissance to identify sites running the TrueBooker plugin.
2. Attacker probes the WordPress application to locate the password reset endpoint provided by the TrueBooker plugin.
3. Attacker identifies a target user's username or email address (e.g., an administrator).
4. Attacker submits a forged password reset request to the vulnerable endpoint.
5. The plugin fails to perform server-side verification of the requestor's identity, accepting the reset request.
6. The plugin updates the password or facilitates a reset for the targeted account.
7. Attacker logs in to the application as the compromised user.
8. Attacker gains full administrative control, potentially deploying further backdoors or exfiltrating sensitive appointment data.

## Impact

Successful exploitation leads to a total account takeover, granting attackers administrative access to the WordPress site. Potential consequences include unauthorized access to customer appointment data, modification of site content, installation of web shells for persistent access, and the potential for lateral movement within the hosting infrastructure.

## Recommendation

* Update the TrueBooker - Appointment Booking and Scheduler System plugin to the latest version immediately to remediate CVE-2026-14364.
* Monitor web server logs for suspicious or high-frequency POST requests targeting password reset endpoints associated with the plugin (look for unusual source IPs or volume).
* Conduct an audit of WordPress administrator accounts for suspicious activity or recent unauthorized password changes.
* Disable the plugin temporarily if an immediate update is not feasible.
