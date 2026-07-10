---
title: Amelia Booking WordPress Plugin Insecure Direct Object Reference Vulnerability
slug: 2024-01-29-amelia-wordpress-idor
description: The Amelia Booking plugin for WordPress versions 9.1.2 and earlier is vulnerable to Insecure Direct Object References (IDOR), allowing authenticated attackers with customer-level permissions or higher to change user passwords and potentially compromise administrator accounts.
date: "2024-01-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - idor
  - privilege-escalation
  - CVE-2026-2931
vendors:
  - Amelia Booking
products:
  - Amelia Booking plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2931
rules:
  - title: Amelia Booking Plugin IDOR Password Reset Attempt
    description: Detects potential exploitation of CVE-2026-2931, an IDOR vulnerability in the Amelia Booking plugin, by monitoring for unauthorized password reset attempts via HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-2931
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Amelia Booking Plugin Unauthorized User Data Modification
    description: Detects potential exploitation of CVE-2026-2931, an IDOR vulnerability in the Amelia Booking plugin, by monitoring for unauthorized modifications to user data via HTTP requests.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-2931
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Amelia Booking plugin, a popular WordPress plugin for scheduling and managing appointments, contains a critical vulnerability related to Insecure Direct Object References (IDOR). Specifically, versions 9.1.2 and earlier of the plugin are susceptible to this flaw. This vulnerability allows attackers with authenticated customer-level privileges or higher to bypass authorization checks and directly access sensitive user data, potentially leading to account takeover. The vulnerability resides within the pro version of the Amelia Booking plugin, which shares the same slug as the standard version, increasing the attack surface. Successful exploitation could lead to unauthorized password resets, data breaches, and complete compromise of the WordPress installation.

## Attack Chain

1. An attacker gains customer-level or higher access to a WordPress installation using the Amelia Booking plugin (version 9.1.2 or earlier).
2. The attacker identifies the vulnerable endpoint within the Amelia Booking plugin responsible for user profile management, specifically password reset functionality.
3. The attacker crafts a malicious HTTP request targeting the vulnerable endpoint, manipulating user IDs to target other users, including administrators.
4. Due to the IDOR vulnerability, the plugin fails to properly validate the attacker's authorization to modify the target user's data.
5. The attacker successfully triggers a password reset for the targeted user account by leveraging the manipulated request.
6. The attacker uses the password reset mechanism to set a new password for the target user.
7. The attacker logs into the targeted user's account using the newly set password.
8. If the compromised account is an administrator account, the attacker gains full control over the WordPress installation.

## Impact

Successful exploitation of this IDOR vulnerability in the Amelia Booking plugin could result in complete compromise of a WordPress website. An attacker with customer-level access could escalate privileges to an administrator account, leading to data breaches, defacement of the website, or installation of malicious plugins. The impact is high because any authenticated user can potentially escalate privileges. This issue affects all organizations using vulnerable versions of the Amelia Booking plugin.

## Recommendation

*   Immediately update the Amelia Booking plugin to the latest version, which contains a patch for CVE-2026-2931.
*   Monitor web server logs (category `webserver`, product `linux` or `windows`) for suspicious POST requests to the Amelia Booking plugin's endpoints related to user management and password resets.
*   Implement rate limiting on password reset functionality to mitigate brute-force attacks and unauthorized password changes.
*   Deploy the Sigma rule to your SIEM (below) to detect attempts to exploit this IDOR vulnerability by monitoring for unauthorized modifications to user passwords via HTTP requests.
