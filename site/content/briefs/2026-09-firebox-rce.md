---
title: Remote Code Execution in FireBox WooCommerce Plugin
slug: 2026-09-firebox-rce
description: The FireBox WordPress plugin is vulnerable to authenticated Remote Code Execution via an insufficiently validated blacklist and improper input sanitization in the firebox_meta REST endpoint.
date: "2026-09-09T03:51:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:firebox:firebox:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - wordpress
  - rce
  - authentication-bypass
vendors:
  - FireBox
products:
  - FireBox – WooCommerce Popup Builder, Exit Intent Popup, Email Optin & Cart Abandonment (<= 3.1.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The FireBox plugin for WordPress is vulnerable to Remote Code Execution ... via the value function.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This makes it possible for authenticated attackers ... to execute code on the server.
    confidence_band: high
cves:
  - id: CVE-2026-76801
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76801
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade FireBox plugin to version > 3.1.10
      owner: IT Operations
      due: 24h
      evidence: Source states all versions up to 3.1.10 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Remove Author-level access for suspicious or unused accounts
      owner: IT Operations
      addresses: Privilege escalation in Migrator::preserveCampaignRoleAccess
      evidence: Source identifies Author role cap escalation during migration
---

The FireBox plugin for WordPress (all versions up to and including 3.1.10) contains a critical Remote Code Execution (RCE) vulnerability. The flaw exists in the Executer::allowedToRun() function, which relies on a regex blacklist that fails to restrict sensitive WordPress core functions such as wp_insert_user, update_option, and file_put_contents. Because the plugin does not perform adequate input sanitization on PHP condition rule values passed through the firebox_meta REST endpoint, an attacker can supply malicious payloads.

Furthermore, a privilege escalation vector exists within the Migrator::preserveCampaignRoleAccess() function. When updating from versions prior to 3.1.10, the plugin automatically assigns edit_fireboxes and publish_fireboxes capabilities to the Author role. This effectively lowers the barrier to entry for exploitation, allowing any authenticated user with Author-level privileges to achieve server-side code execution.

## Impact

Successful exploitation allows authenticated attackers with Author-level access to execute arbitrary PHP code on the underlying web server. This can lead to full site compromise, unauthorized database modification, or the installation of persistent web shells. The vulnerability affects all users running FireBox version 3.1.10 or earlier.

## Recommendation

Prioritized actions for security and IT teams:

- Update the FireBox plugin to the latest version immediately to resolve the vulnerable regex blacklist and sanitize inputs in the firebox_meta endpoint.
- Audit existing user accounts with Author roles to identify and remediate accounts that may have gained unnecessary permissions following the migration to version 3.1.10.
- Monitor REST API traffic for POST requests targeting the 'firebox_meta' endpoint containing suspicious function calls or serialized PHP objects.
- Implement strict web application firewall (WAF) rules to inspect incoming requests for function names like 'file_put_contents' or 'wp_insert_user' within JSON bodies destined for the WordPress REST API.
