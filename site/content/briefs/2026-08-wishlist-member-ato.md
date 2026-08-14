---
title: 'CVE-2026-12949: Unauthenticated Account Takeover in Wishlist Member Plugin'
slug: 2026-08-wishlist-member-ato
description: The Wishlist Member plugin for WordPress contains an account takeover vulnerability via insufficient verification of registration data in the wpm_register function, allowing unauthenticated attackers to overwrite administrator accounts.
date: "2026-08-14T08:06:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Wishlist Member
products:
  - Wishlist Member
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for unauthenticated attackers to take over any existing WordPress account.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: making full privilege escalation a direct consequence of the takeover.
    confidence_band: high
cves:
  - id: CVE-2026-12949
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12949
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Wishlist Member plugin to version > 3.34.1
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Search web logs for POST requests to registration paths with mergewith parameter
      technique_id: T1078
      data_needed:
        - webserver logs (cs-uri-query, cs-method)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies POST mergewith as the exploit vector
---

The Wishlist Member plugin for WordPress (versions 3.34.1 and below) is susceptible to a critical account takeover vulnerability (CVE-2026-12949) caused by insufficient verification of data authenticity within the wpm_register() function. Attackers can exploit this flaw by submitting specific POST parameters (mergewith and wpm_id) to the registration endpoint. The plugin fails to verify if the mergewith parameter, which accepts a numeric WordPress user ID, is cryptographically bound to the current registration transaction. 

By supplying an arbitrary user ID, an attacker can force the application to execute wp_update_user() and a direct $wpdb UPDATE, overwriting the victim's credentials, email, and name. Critically, the plugin suppresses WordPress's built-in notification emails for password or email address changes. If the wpm_id parameter is set to a non-existent membership level, the plugin skips the role update, preserving the target user's existing permissions. This allows unauthenticated attackers to silently elevate their access to an administrator level, posing a significant risk to site integrity and data security.

## Attack Chain

1. Attacker identifies a WordPress site running Wishlist Member <= 3.34.1.
2. Attacker enumerates the target's numeric User ID (e.g., ID 1 for administrator).
3. Attacker crafts a malicious POST request to the wpm_register() endpoint.
4. Attacker includes the target's User ID in the 'mergewith' POST parameter.
5. Attacker includes a non-existent value in the 'wpm_id' parameter to bypass role modifications.
6. The plugin processes the request and executes wp_update_user() and $wpdb updates using attacker-supplied credentials.
7. The plugin suppresses standard WordPress security notification emails.
8. Attacker gains full unauthorized access to the target account, including administrative privileges.

## Impact

Successful exploitation allows unauthenticated attackers to take over any existing user account, including those with administrator privileges. Given that the plugin suppresses security notifications, the compromise may go undetected by site owners. This leads to full administrative compromise, data exfiltration, backdooring, and potential full-site control.

## Recommendation

* Update the Wishlist Member plugin to a patched version beyond 3.34.1 immediately.
* Monitor web server access logs for POST requests to registration endpoints containing the 'mergewith' and 'wpm_id' parameters.
* Implement file integrity monitoring and database auditing to detect unauthorized modifications to the wp_users table.
* Review web application logs (sc-status, cs-uri-stem) for suspicious registration patterns targeting high-privilege IDs.
