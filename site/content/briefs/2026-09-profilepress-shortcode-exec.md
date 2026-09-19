---
title: Arbitrary Shortcode Execution in ProfilePress Plugin
slug: 2026-09-profilepress-shortcode-exec
description: The ProfilePress WordPress plugin is vulnerable to arbitrary shortcode execution in versions up to 4.17.2, allowing authenticated users with subscriber-level access to execute arbitrary shortcodes.
date: "2026-09-19T10:11:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:profilepress:paid_membership_plugin,_ecommerce,_user_registration_form,_login_form,_user_profile_&_restrict_content:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - rce
vendors:
  - ProfilePress
products:
  - Paid Membership Plugin, Ecommerce, User Registration Form, Login Form, User Profile & Restrict Content (<= 4.17.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The software allows users to execute an action that does not properly validate a value before running do_shortcode.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This makes it possible for authenticated attackers... to execute arbitrary shortcodes.
    confidence_band: high
cves:
  - id: CVE-2026-85658
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85658
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade ProfilePress plugin to version 4.17.3 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85658 remediation
  mitigation_plan:
    - priority: immediate
      action: Identify and disable ProfilePress plugin usage for unauthorized subscriber roles
      owner: IT Operations
      addresses: CVE-2026-85658
      evidence: Source support for version limitation
---

The ProfilePress plugin (formerly known as Paid Membership Plugin, Ecommerce, User Registration Form, Login Form, User Profile & Restrict Content) for WordPress is affected by an arbitrary shortcode execution vulnerability (CVE-2026-85658). The vulnerability exists in all versions up to and including 4.17.2. The flaw is caused by insufficient validation of user-supplied values before they are processed by the WordPress 'do_shortcode' function. Authenticated attackers with at least subscriber-level permissions can leverage this vulnerability to execute arbitrary shortcodes within the WordPress environment. This can be exploited to access restricted content, potentially escalate privileges depending on the available shortcodes within the installation, or perform other unauthorized actions available to the WordPress shortcode system.

## Impact

The vulnerability allows authenticated users with low-level subscriber access to trigger arbitrary shortcodes. In a WordPress environment, this can lead to unauthorized information disclosure, bypass of content restrictions, or the execution of functional components intended for administrators, effectively increasing the attacker's capabilities beyond their assigned role.

## Recommendation

Update the ProfilePress plugin to the latest available version (beyond 4.17.2) immediately. If an update is not currently possible, restrict access to the registration and profile management pages for unprivileged accounts or disable the plugin until a patch is applied.
