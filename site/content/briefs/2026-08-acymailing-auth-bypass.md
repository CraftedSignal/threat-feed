---
title: Authorization Bypass in AcyMailing WordPress Plugin
slug: 2026-08-acymailing-auth-bypass
description: An authorization bypass vulnerability in AcyMailing allows authenticated subscribers to hijack WordPress password reset emails by modifying notification template BCC fields.
date: "2026-08-11T21:50:42Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Acyba
products:
  - AcyMailing (10.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The AcyMailing plugin for WordPress is vulnerable to an authorization bypass flaw that allows authenticated users with subscriber-level permissions to modify the BCC field of system notification templates.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: enabling account takeover via the captured reset link
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update AcyMailing to version 10.11.2
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-15426 remediation requirements
  mitigation_plan:
    - priority: immediate
      action: Disable 'Send website emails with AcyMailing' if immediate patching is not possible
      owner: IT Operations
      addresses: CVE-2026-15426
      evidence: Successful exploitation requires the site administrator to have enabled the Send website emails with AcyMailing option
---

The AcyMailing plugin for WordPress (versions 10.11.1 and earlier) contains an authorization bypass vulnerability (CVE-2026-15426) that allows authenticated users with low-level privileges (subscriber) to modify sensitive email notification templates. If the site administrator has enabled the "Send website emails with AcyMailing" feature, the plugin intercepts WordPress core notification emails and routes them through its internal templating engine.

Attackers exploit this by modifying the BCC field of the 'acy_notification_cms' template. By injecting an attacker-controlled email address into the BCC field, any password-reset request initiated by a site administrator is copied to the attacker. The attacker then intercepts the password-reset link to gain unauthorized access to the administrator account. This vulnerability poses a significant risk to WordPress sites where AcyMailing is configured to handle system-generated emails.

## Attack Chain

1. Attacker authenticates to a target WordPress site as a user with 'subscriber' level access or higher.
2. Attacker verifies that the target site has the AcyMailing "Send website emails with AcyMailing" setting enabled.
3. Attacker sends a crafted request to the plugin's configuration endpoint to modify the 'acy_notification_cms' template.
4. Attacker inserts an external email address controlled by the attacker into the BCC parameter of the template.
5. Attacker triggers a legitimate WordPress password-reset request targeting an administrator account (e.g., via /wp-login.php?action=lostpassword).
6. The WordPress backend generates a password-reset notification, which is processed by AcyMailing.
7. AcyMailing appends the attacker's email to the BCC list and dispatches the notification to both the administrator and the attacker.
8. Attacker receives the email containing the password-reset link and completes the account takeover.

## Impact

Successful exploitation leads to full administrative account takeover of the affected WordPress site. This grants the attacker elevated privileges, allowing for site-wide data exfiltration, deployment of malicious scripts, or further compromise of the web server hosting environment. All versions up to 10.11.1 are affected.

## Recommendation

1. Immediately update the AcyMailing plugin to version 10.11.2 or later to resolve CVE-2026-15426.
2. Audit active WordPress user accounts for suspicious "subscriber" roles that may be involved in testing or exploitation activities.
3. Review webserver logs for unauthorized POST requests directed at AcyMailing configuration endpoints that manage template settings.
4. Temporarily disable the "Send website emails with AcyMailing" feature if an immediate update is not possible.
