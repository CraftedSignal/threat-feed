---
title: Privilege Escalation in Groundhogg WordPress Plugin via Contact Rebinding
slug: 2026-10-groundhogg-priv-esc
description: Authenticated attackers can perform privilege escalation in Groundhogg versions 4.9 and below by rebinding contact records to arbitrary user IDs via the REST API and leveraging automated login links.
date: "2026-10-03T04:53:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:groundhogg:groundhogg:*:*:*:*:*:wordpress:*:*
tags:
  - privilege-escalation
  - wordpress
  - web-application
vendors:
  - Groundhogg
products:
  - Groundhogg — CRM, Newsletters, and Marketing Automation (<= 4.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability exists because the create_contact function in the v3 REST endpoint is gated solely by the add_contacts capability and forwards the full request payload into the upsert path, bypassing the ownership guard.
    confidence_band: high
cves:
  - id: CVE-2026-97644
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97644
rules:
  - title: Detects CVE-2026-97644 Exploitation - Unauthorized Contact Upsert
    description: Detects potential exploitation of CVE-2026-97644 by identifying POST requests to the Groundhogg contact API containing a user_id parameter.
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Groundhogg to a version patched against CVE-2026-97644
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-97644 advisory
  hunt_leads:
    - lead: Search logs for POST /gh/v3/contacts with user_id parameter
      technique_id: T1068
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability analysis indicates this is the primary entry point
  mitigation_plan:
    - priority: immediate
      action: Upgrade Groundhogg plugin
      owner: IT Operations
      addresses: CVE-2026-97644
      evidence: NVD
---

The Groundhogg plugin for WordPress (versions 4.9 and earlier) contains a critical vulnerability (CVE-2026-97644) that enables authenticated users with the 'add_contacts' capability (such as Sales Representatives) to escalate privileges to Administrator. The issue resides in the v3 REST endpoint `POST /gh/v3/contacts`, where the `create_contact` function fails to restrict the `user_id` field. By manipulating the request payload, an attacker can rebind a contact record to an administrative user ID. 

Once the contact record is rebound, the attacker can interact with the v4 email-test endpoint (`POST /gh/v4/emails/test`), which is accessible to users with the 'send_emails' capability. This endpoint generates an `auto_login_url` bound to the contact record. By consuming this one-time permissions key, the attacker forces the system to call `wp_set_auth_cookie()`, granting them a fully authenticated administrative session. This vulnerability poses a severe risk to WordPress instances utilizing the plugin for marketing automation and CRM purposes, as it provides a clear path to complete site takeover by low-privileged users.

## Attack Chain

1. Attacker authenticates to the WordPress instance with at least 'Sales Representative' or equivalent privileges.
2. Attacker crafts a `POST` request to the Groundhogg v3 API endpoint `/gh/v3/contacts`.
3. Attacker includes the `user_id` field in the request payload, targeting the ID associated with a WordPress Administrator.
4. The `create_contact` function performs an upsert operation that overwrites the existing contact record association.
5. Attacker sends a `POST` request to the v4 email-test endpoint at `/gh/v4/emails/test`.
6. The plugin generates an `auto_login_url` mapped to the now-rebound administrative contact.
7. Attacker retrieves the auto-login URL from the test notification.
8. Attacker accesses the URL, triggering `wp_set_auth_cookie()` and establishing an authenticated session as the Administrator.

## Impact

Successful exploitation results in full administrative access to the affected WordPress installation. This allows an attacker to execute arbitrary code, modify site content, access sensitive customer data stored within the CRM, and install malicious plugins or backdoors, leading to total compromise of the web application and its underlying data.

## Recommendation

Prioritized actions for security teams:
- Patch immediately: Upgrade the Groundhogg plugin to the version containing the fix for CVE-2026-97644.
- Audit logs for the specified REST endpoints: Monitor web server access logs for `POST` requests to `/gh/v3/contacts` and `/gh/v4/emails/test` originating from non-administrative user accounts.
- Restrict access: Limit WordPress user capabilities to ensure only trusted users hold the 'add_contacts' and 'send_emails' privileges until patching is completed.
- Review administrative accounts: Audit all WordPress user accounts for suspicious additions or modifications to user profiles performed after the vulnerability was publicly disclosed.
