---
title: Privilege Escalation Vulnerability in Nokri Job Board WordPress Theme
slug: 2026-09-nokri-theme-privilege-escalation
description: The Nokri Job Board WordPress theme (<= 1.6.4) is vulnerable to privilege escalation via a missing capability check in the 'nokri_account_member_permissions' function, allowing authenticated subscribers to escalate access.
date: "2026-09-05T13:32:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nokri:job_board_wordpress_theme:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - web-application-vulnerability
vendors:
  - WordPress
products:
  - Nokri – Job Board WordPress Theme (<= 1.6.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to add new Subscriber users with employer account member permissions, who in turn can escalate privileges by updating the email address of any user, including Administrator users.
    confidence_band: high
cves:
  - id: CVE-2025-9049
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-9049
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update Nokri - Job Board WordPress Theme to a version above 1.6.4.
      owner: IT Operations
      due: 24h
      evidence: Source states theme is vulnerable in versions up to 1.6.4.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Nokri - Job Board WordPress Theme to current version.
      owner: IT Operations
      addresses: CVE-2025-9049
      evidence: NVD vulnerability entry.
---

The Nokri - Job Board WordPress Theme for WordPress, in all versions up to and including 1.6.4, contains a critical security vulnerability involving a missing capability check within the 'nokri_account_member_permissions' function. This flaw allows an authenticated attacker, specifically those with Subscriber-level privileges, to interact with the function to add new users as employer account members. By abusing this capability, an attacker can modify the email addresses of existing users, including those with Administrator privileges. This email modification allows the attacker to trigger password reset procedures, effectively facilitating full account takeover of administrative accounts. The vulnerability stems from improper input validation and insufficient authorization controls within the theme's member management features, posing a significant risk to the integrity and security of the WordPress instance.

## Attack Chain

1. Attacker authenticates to the target WordPress site with low-privilege Subscriber credentials.
2. Attacker crafts an HTTP POST request targeting the vulnerable 'nokri_account_member_permissions' function.
3. The vulnerable theme code fails to verify if the requesting user possesses administrative or sufficient employer-level permissions.
4. Attacker injects parameters to add a new Subscriber user with employer-level account member privileges.
5. Attacker logs into or uses the elevated employer member account to access user profile modification features.
6. Attacker updates the email address of a target Administrator account to an attacker-controlled email address.
7. Attacker initiates a standard 'Forgot Password' request for the hijacked Administrator account.
8. Attacker receives the password reset token at the attacker-controlled email address to complete the account takeover.

## Impact

Successful exploitation of this vulnerability leads to full administrative account takeover. Attackers can gain control over the entire WordPress site, potentially resulting in data exfiltration, unauthorized content modification, installation of malicious plugins, or complete site defacement. The scope is limited to WordPress installations utilizing the Nokri - Job Board WordPress Theme versions 1.6.4 and below.

## Recommendation

Prioritize the immediate update of the Nokri - Job Board WordPress Theme to the latest available version provided by the vendor. In environments where immediate patching is not possible, implement strict access controls on registration and user modification endpoints. Enable detailed server-side request logging to monitor for unauthorized calls to the 'nokri_account_member_permissions' function.
