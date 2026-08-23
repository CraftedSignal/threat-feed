---
title: Authorization Bypass in Security Hardener Plugin for WordPress
slug: 2026-08-security-hardener-vuln
description: The Security Hardener plugin for WordPress contains an authorization bypass vulnerability in versions 2.4.4 and earlier that allows authenticated subscribers to escalate privileges to administrator.
date: "2026-08-23T01:34:06Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - Security Hardener
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers with Subscriber-level access and above to create new Administrator accounts.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.001
    technique_name: 'Create Account: Local Account'
    evidence: This makes it possible for authenticated attackers with Subscriber-level access and above to create new Administrator accounts.
    confidence_band: high
cves:
  - id: CVE-2026-16149
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16149
rules:
  - title: Detect CVE-2026-16149 Exploitation - Unauthorized REST API User Management
    description: Detects unauthorized attempts to create or modify users via the REST API, potentially exploiting the Security Hardener authorization bypass.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Security Hardener plugin to version 2.4.5 or higher
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-16149 vulnerability advisory
  hunt_leads:
    - lead: Search logs for REST API user modifications from non-admin accounts
      technique_id: T1068
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows user modification via REST API
---

The Security Hardener plugin for WordPress (versions 2.4.4 and earlier) contains a critical Missing Authorization vulnerability, assigned CVE-2026-16149. The flaw stems from the plugin's user-enumeration protection feature, which hooks into the WordPress `rest_endpoints` filter. Specifically, the `secure_user_endpoints()` function incorrectly overwrites the permission callbacks for the `/wp/v2/users` and `/wp/v2/users/(?P<id>[\d]+)` REST API routes. 

By replacing WordPress Core's granular capability checks - such as `create_users`, `promote_user`, `edit_users`, and `delete_users` - with a simplistic `is_user_logged_in()` check, the plugin inadvertently permits any authenticated user to perform administrative actions. Since this protection feature is enabled by default upon installation, no specific configuration is required for an attacker to exploit the flaw. Successful exploitation allows a standard Subscriber account to create new Administrator accounts or overwrite the credentials of existing administrative users via crafted REST API requests.

## Impact

Successful exploitation results in full administrative takeover of the WordPress site. An attacker can create new administrator accounts, delete content, modify site configuration, or gain remote code execution capabilities through administrative features like plugin/theme management. The vulnerability affects any WordPress instance where the Security Hardener plugin is active, posing a significant risk to site integrity and data security.

## Recommendation

- Update the Security Hardener plugin to the latest version immediately to patch CVE-2026-16149.
- Audit existing user accounts for suspicious additions or modifications, specifically looking for new users created with administrator roles.
- Review WordPress REST API access logs for anomalous POST, PUT, PATCH, or DELETE requests directed at the `/wp-json/wp/v2/users` endpoint originating from low-privileged accounts.
- If patching is not immediately feasible, disable the user-enumeration protection feature within the Security Hardener plugin settings.
