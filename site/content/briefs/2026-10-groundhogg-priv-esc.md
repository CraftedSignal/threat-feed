---
title: CVE-2026-104725 Privilege Escalation in Groundhogg WordPress Plugin
slug: 2026-10-groundhogg-priv-esc
description: The Groundhogg WordPress plugin is vulnerable to privilege escalation allowing authenticated users with 'edit_contacts' capability to assume administrator identities via insecure user ID reassignment and auto-login link generation.
date: "2026-10-10T07:50:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:groundhogg:groundhogg:*:*:*:*:*:wordpress:*:*
vendors:
  - Groundhogg
products:
  - Groundhogg - CRM, Newsletters, and Marketing Automation (<= 4.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Groundhogg WordPress plugin is vulnerable to Privilege Escalation... this makes it possible for authenticated attackers... to escalate their privileges to administrator.
    confidence_band: high
cves:
  - id: CVE-2026-104725
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104725
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Groundhogg plugin to the version containing the fix for CVE-2026-104725.
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Upgrade Groundhogg to the latest available patched version.
      owner: IT Operations
      addresses: CVE-2026-104725
      evidence: NVD vulnerability details
---

Groundhogg CRM, Newsletters, and Marketing Automation plugin for WordPress (versions 4.9 and below) is vulnerable to a critical privilege escalation flaw (CVE-2026-104725). The vulnerability exists within the `process_edit()` function, which fails to perform proper ownership and capability validation when processing the `user` parameter. 

An attacker holding the `edit_contacts` capability - commonly assigned to sales representative roles - can exploit this to reassign a contact record to an arbitrary WordPress user ID, including those belonging to administrators. By then utilizing the plugin's note-creation functionality, the attacker can insert the `{auto_login_link}` tag. This action triggers the generation of an auto-login URL. Because the attacker has sufficient permissions to view the note, they can extract the auto-login link and authenticate as the administrator, gaining full control over the WordPress instance. This bypasses the need for the `edit_users` or `promote_users` administrative capabilities.

## Attack Chain

1. Attacker authenticates as a user with at least 'edit_contacts' capability (e.g., Sales Representative).
2. Attacker interacts with the 'process_edit' function via an HTTP POST request to the Groundhogg API/interface.
3. Attacker modifies the 'user' parameter for a contact record to match an administrator's WordPress User ID.
4. Attacker submits a request to add a note to the now administrator-linked contact record.
5. Attacker includes the '{auto_login_link}' replacement tag within the body of the new note.
6. The plugin processes the note, generating a valid permissions-key URL for the administrator account.
7. Attacker retrieves the note content to obtain the generated auto-login URL.
8. Attacker visits the URL to successfully authenticate as the targeted administrator.

## Impact

Successful exploitation results in full administrative access to the WordPress site. This allows attackers to install malicious plugins, modify site content, exfiltrate user data, or conduct further post-exploitation activities. The vulnerability affects all users running Groundhogg versions 4.9 and lower.

## Recommendation

1. Upgrade to the latest version of the Groundhogg CRM, Newsletters, and Marketing Automation plugin immediately to patch CVE-2026-104725.
2. Audit current WordPress user roles to ensure only trusted users hold the 'edit_contacts' capability.
3. Implement web application firewall (WAF) rules to inspect POST requests directed to Groundhogg endpoint paths for unusual 'user' parameter modifications or the presence of auto-login link patterns.
