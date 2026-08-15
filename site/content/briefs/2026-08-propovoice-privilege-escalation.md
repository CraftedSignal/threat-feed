---
title: Propovoice Plugin Privilege Escalation Vulnerability
slug: 2026-08-propovoice-privilege-escalation
description: An improper capability check in the Propovoice plugin for WordPress (<= 1.7.8) allows authenticated users with the 'ndpv_manager' role to escalate their privileges to administrator by exploiting the REST API's user creation function.
date: "2026-08-15T04:16:54Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - 'Propovoice: All-in-One Client Management System'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'The Propovoice: All-in-One Client Management System plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 1.7.8.'
    confidence_band: high
cves:
  - id: CVE-2026-15312
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15312
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Propovoice plugin to version 1.7.9 or later to remediate CVE-2026-15312.
      owner: IT Operations
      due: 24h
      evidence: Vendor vulnerability advisory indicates versions 1.7.8 and below are vulnerable.
---

The Propovoice: All-in-One Client Management System plugin for WordPress contains a critical privilege escalation vulnerability (CVE-2026-15312) in all versions up to and including 1.7.8. The vulnerability originates in the plugin's REST API, specifically within the `create()` function. This function fails to implement necessary authorization checks to verify if the requesting user possesses the `promote_users` capability before modifying user roles. Furthermore, the endpoint fails to validate user-supplied `role` parameters against an allowlist, allowing an attacker to pass arbitrary role names directly to the `WP_User::set_role()` WordPress function.

This flaw is particularly significant because it allows any user already holding the `ndpv_manager` role - a role granted by the Propovoice plugin itself - to elevate their account or create new accounts with full administrative privileges. This provides attackers with a path to full site compromise once they have obtained lower-level management access, making the plugin a high-value target for privilege escalation within WordPress environments.

## Attack Chain

1. Attacker obtains valid credentials for a user account with the `ndpv_manager` capability assigned by the Propovoice plugin.
2. Attacker logs into the WordPress environment using these credentials to initiate authenticated sessions.
3. Attacker identifies the vulnerable REST API endpoint exposed by the Propovoice plugin associated with the `create()` function.
4. Attacker constructs a malicious HTTP POST request targeting the endpoint, embedding the `role` parameter set to `administrator`.
5. The server-side REST API fails to perform a capability check for `promote_users` and neglects to validate the `role` input against an allowlist.
6. The `WP_User::set_role()` function is invoked by the plugin with the attacker-supplied `administrator` value.
7. The user account is promoted, or a new user is created, with full administrative access to the WordPress site.
8. Attacker uses administrative access to perform further malicious actions, such as plugin/theme modification or arbitrary code execution.

## Impact

Successful exploitation results in full administrative control over the affected WordPress instance. Attackers can leverage this access to modify site content, install malicious plugins, gain persistence, and exfiltrate sensitive data managed within the CRM system. This vulnerability impacts any WordPress site utilizing Propovoice versions 1.7.8 or earlier.

## Recommendation

* Immediately update the Propovoice plugin to the latest patched version available from the vendor.
* Audit existing WordPress user accounts for unexpected administrative role assignments occurring within the same timeframe as access logs showing suspicious REST API activity.
* Monitor webserver access logs for anomalous POST requests to the REST API endpoints associated with user management in the Propovoice plugin.
