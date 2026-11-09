---
brief_id: brief-2026-11-09-wp-base-privesc
event_id: brief-2026-11-09-wp-base-privesc
revision: 1
activity_at: "2026-11-09T15:51:39Z"
title: 'WP BASE Booking of Appointments, Services and Events: Privilege escalation (CVE-2026-123064)'
slug: 2026-11-wp-base-privesc
description: The WP BASE Booking of Appointments, Services and Events plugin before version 6.5.1 contains a vulnerability that allows authenticated subscribers to create administrative accounts and escalate privileges.
date: "2026-11-09T15:51:39Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation for user-creation audit logging.
cpes:
  - cpe:2.3:a:wp_base:wp_base_booking_of_appointments_services_and_events:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - cms
vendors:
  - WP BASE
products:
  - WP BASE Booking of Appointments, Services and Events (< 6.5.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated users with Subscriber-level access and above to create a new administrator account and thereby escalate their privileges.
    confidence_band: high
cves:
  - id: CVE-2026-123064
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123064
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade WP BASE Booking of Appointments, Services and Events to 6.5.1
      owner: IT Operations
      due: 24h
      evidence: Vulnerability fixed in 6.5.1 per NVD.
  hunt_leads:
    - lead: Hunt for unauthorized administrator account creation events
      technique_id: T1068
      data_needed:
        - WordPress user_register action hooks
        - Audit logs showing new user creation by existing subscribers
        - Database logs (wp_users and wp_usermeta) for role changes
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The flaw allows subscribers to create new administrator accounts.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to 6.5.1
      owner: IT Operations
      addresses: CVE-2026-123064
      evidence: Official patch version
---

The WP BASE Booking of Appointments, Services and Events plugin for WordPress is affected by a privilege escalation vulnerability (CVE-2026-123064) due to insufficient access control on a user-creation action. Authenticated users with Subscriber-level access can exploit this flaw to register new administrator accounts. The vulnerability is confirmed in versions prior to 6.5.1.

## Impact

An attacker with an active subscriber-level account can achieve full administrative access to the affected WordPress instance, leading to complete site compromise.

## Recommendation

- Update the WP BASE Booking of Appointments, Services and Events plugin to version 6.5.1 or later immediately.
- Audit the WordPress user database for unauthorized administrator accounts created after the plugin's last update.
- Temporarily disable user registration functionality if patching cannot be performed immediately.
