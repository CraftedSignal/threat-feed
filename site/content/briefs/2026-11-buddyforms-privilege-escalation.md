---
brief_id: brief-2026-11-06-buddyforms-privilege-escalation
event_id: brief-2026-11-06-buddyforms-privilege-escalation
revision: 1
activity_at: "2026-11-06T13:09:31Z"
title: 'BuddyForms: Privilege escalation via form submission (CVE-2026-107622)'
slug: 2026-11-buddyforms-privilege-escalation
description: The BuddyForms WordPress plugin is vulnerable to unauthenticated privilege escalation via a form-type confusion flaw that allows attackers to create administrator accounts.
date: "2026-11-06T13:09:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:buddyforms:buddyforms:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - vulnerability
  - privilege-escalation
vendors:
  - BuddyForms
products:
  - BuddyForms (<= 2.10.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: By injecting a rogue BuddyForms form configuration containing a modified new_user_role, an attacker can register a new WordPress account with administrator-level privileges.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Exploitation requires the WordPress site to have "Anyone can register" enabled and at least one public BuddyForms form attached to a page.
    confidence_band: high
cves:
  - id: CVE-2026-107622
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107622
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch BuddyForms plugin to version 2.10.6 or later.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability confirmed in versions <= 2.10.5.
    - action: Check WordPress user database for unauthorized administrator accounts created recently.
      owner: SOC
      due: 24h
      evidence: Attack results in administrator account creation.
  hunt_leads:
    - lead: Inspect web server access logs for anomalous POST requests to BuddyForms submission endpoints containing unexpected parameters in buddyforms_options.
      technique_id: T1068
      data_needed:
        - webserver logs
        - application logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves injecting configurations via POST requests to the plugin.
---

The BuddyForms plugin for WordPress (versions 2.10.5 and earlier) contains a critical privilege escalation vulnerability due to improper input validation and missing authorization checks. The plugin's public submission handler, `buddyforms_form_response_no_ajax()`, improperly trusts the `bf_post_type` parameter when handling new object creation. An unauthenticated attacker can supply a malicious form configuration via the `buddyforms_options` parameter to override the `new_user_role` setting. This allows an attacker to register a new account on a site where "Anyone can register" is enabled, granting that account administrator-level privileges.

## Attack Chain

1. Attacker identifies a WordPress site with the BuddyForms plugin and "Anyone can register" enabled.
2. Attacker crafts a POST request to the `buddyforms_form_response_no_ajax` handler.
3. Attacker specifies a malicious `bf_post_type` and injects an arbitrary form configuration via the `buddyforms_options` parameter.
4. The plugin fails to validate the request or verify authorization, permitting the creation of a rogue form entry in the global registry.
5. The rogue form is configured to assign the administrator role to new registrants via the `new_user_role` field.
6. Attacker submits a user registration through the newly created rogue form.
7. WordPress creates the account with administrative privileges, resulting in full site compromise.

## Impact

Successful exploitation allows an unauthenticated attacker to gain full administrative control over the WordPress site.

## Recommendation

* Immediately update the BuddyForms plugin to the latest patched version (post-2.10.5).
* If an update cannot be applied immediately, disable public registration on the WordPress site.
* Audit existing BuddyForms forms for unauthorized configuration changes or unexpected `new_user_role` values.
* Audit the WordPress user database for newly created administrator accounts.
