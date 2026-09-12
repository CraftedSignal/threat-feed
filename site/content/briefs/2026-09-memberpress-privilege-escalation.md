---
title: Privilege Escalation in MemberPress Corporate Accounts WordPress Plugin
slug: 2026-09-memberpress-privilege-escalation
description: The MemberPress Corporate Accounts plugin for WordPress contains a mass assignment vulnerability that allows authenticated users with corporate sub-account privileges to escalate to administrator by injecting unauthorized fields during user creation.
date: "2026-09-12T13:19:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:memberpress:memberpress_corporate_accounts:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - vulnerability
vendors:
  - MemberPress
products:
  - MemberPress Corporate Accounts (<= 1.5.39)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The MemberPress Corporate Accounts plugin for WordPress is vulnerable to Privilege Escalation... due to a mass assignment vulnerability.
    confidence_band: high
cves:
  - id: CVE-2026-15451
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15451
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade MemberPress Corporate Accounts plugin to a version released after 1.5.39
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability affects versions up to and including 1.5.39
  mitigation_plan:
    - priority: immediate
      action: Upgrade MemberPress Corporate Accounts to 1.5.39 or later
      owner: IT Operations
      addresses: CVE-2026-15451
      evidence: NVD vulnerability details
---

The MemberPress Corporate Accounts plugin for WordPress (versions 1.5.39 and earlier) contains a critical security flaw involving improper input validation within the 'add_sub_account_user' function. The plugin performs a mass assignment operation by passing a raw 'userdata' array directly into the 'wp_insert_user' WordPress function without sanitizing sensitive keys. This oversight allows an attacker who already possesses an authenticated account with subscriber-level access and corporate sub-account privileges to supply malicious parameters. By manipulating these parameters, an attacker can modify existing administrative accounts, such as changing their associated email addresses to gain account recovery access, or programmatically create new administrative-level accounts. This vulnerability represents a significant risk to site integrity, as it grants full control over the WordPress environment to unauthorized users.

## Attack Chain

1. Attacker authenticates to the target WordPress site with a valid subscriber account associated with a corporate sub-account.
2. Attacker navigates to the endpoint responsible for the 'add_sub_account_user' functionality within the MemberPress Corporate Accounts plugin.
3. Attacker intercepts the HTTP request and identifies the 'userdata' parameter structure.
4. Attacker injects unauthorized key-value pairs into the 'userdata' payload, specifically targeting role assignment fields (e.g., 'administrator').
5. The plugin function passes the malicious payload to 'wp_insert_user' without verifying input keys against an allowlist.
6. The WordPress database updates or inserts the user object with the elevated permissions requested by the attacker.
7. Attacker logs in or initiates a password reset for the newly created or hijacked administrative account to complete the full takeover of the WordPress instance.

## Impact

Successful exploitation results in full administrative control over the affected WordPress installation. This allows attackers to install malicious plugins, modify site content, exfiltrate sensitive user data, and execute arbitrary code on the server if the WordPress instance has further administrative capabilities enabled. All WordPress installations running the MemberPress Corporate Accounts plugin version 1.5.39 or earlier are vulnerable.

## Recommendation

1. Upgrade the MemberPress Corporate Accounts plugin to the latest version immediately to remediate the mass assignment flaw in 'add_sub_account_user'.
2. Audit all existing user accounts for suspicious additions or modifications to the 'administrator' role that occurred around the time of discovery.
3. Review WordPress administrative logs for unusual user registration activity originating from the plugin's corporate sub-account interface.
