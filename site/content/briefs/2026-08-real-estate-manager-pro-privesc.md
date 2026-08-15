---
title: Privilege Escalation Vulnerability in Real Estate Manager Pro WordPress Plugin
slug: 2026-08-real-estate-manager-pro-privesc
description: The Real Estate Manager Pro plugin for WordPress is vulnerable to privilege escalation via improper capability handling in the allow_attachment_actions function, allowing authenticated attackers to modify administrator accounts.
date: "2026-08-15T10:18:06Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - Real Estate Manager Pro (<= 12.8.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to edit an administrator account and escalate their privileges to Administrator.
    confidence_band: high
cves:
  - id: CVE-2026-15142
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15142
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update Real Estate Manager Pro to a patched version beyond 12.8.6
      owner: IT Operations
      addresses: CVE-2026-15142
      evidence: NVD vulnerability advisory
---

The Real Estate Manager Pro plugin for WordPress, in all versions up to and including 12.8.6, contains a critical vulnerability identified as CVE-2026-15142. The flaw exists within the allow_attachment_actions() function, which fails to correctly validate user capabilities. During the execution of this function, the plugin incorrectly processes user IDs as if they were media attachment IDs.

This flaw allows an authenticated attacker with minimal privileges (Subscriber-level) to bypass standard WordPress role restrictions. By manipulating parameters so that a target administrator's user ID aligns with an existing media attachment ID, an attacker can trigger unauthorized modifications to the account. This can result in a full privilege escalation to the Administrator role, granting the attacker complete control over the WordPress instance. Given the broad potential for site-wide compromise, it is imperative that administrators update to a patched version of the plugin immediately.

## Impact

Successful exploitation of CVE-2026-15142 allows an authenticated user to achieve full administrative control over the target WordPress installation. This impacts all websites utilizing the Real Estate Manager Pro plugin versions 12.8.6 and below. Compromise at the administrator level typically leads to arbitrary code execution, sensitive data theft, and the deployment of additional malicious plugins or backdoors on the server.

## Recommendation

- Update the Real Estate Manager Pro plugin to the latest available version that addresses CVE-2026-15142.
- Audit all administrative user accounts for unauthorized changes if the vulnerable version was previously exposed to untrusted users.
- Implement strict user role restrictions and consider disabling registration for untrusted users on sites utilizing this plugin until updates are applied.
