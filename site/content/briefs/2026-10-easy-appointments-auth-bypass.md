---
title: Authorization Bypass in Easy!Appointments Booking::register
slug: 2026-10-easy-appointments-auth-bypass
description: Easy!Appointments versions 1.6.0 and earlier are vulnerable to an authorization bypass allowing unauthenticated modification of appointments via the Booking::register function.
date: "2026-10-11T14:01:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:easyappointments:easy\!appointments:*:*:*:*:*:*:*:*
vendors:
  - Easy!Appointments
products:
  - Easy!Appointments (<= 1.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can enumerate sequential appointment ids with a self-asserted manage_mode flag to rewrite appointment details.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108758
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Easy!Appointments to a version beyond 1.6.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-108758 is present in versions up to 1.6.0
  hunt_leads:
    - lead: Identify high-frequency, sequential requests to Booking::register or similar endpoints
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers enumerate sequential appointment ids
  mitigation_plan:
    - priority: immediate
      action: Upgrade Easy!Appointments to version > 1.6.0
      owner: IT Operations
      addresses: CVE-2026-108758
      evidence: NVD vulnerability disclosure
---

Easy!Appointments versions 1.6.0 and earlier contain an authorization bypass vulnerability within the Booking::register() function. This flaw permits unauthenticated attackers to manipulate appointment records by supplying an appointment ID without the required management hash. By enumerating sequential appointment IDs and setting a self-asserted 'manage_mode' flag, an attacker can modify appointment details, reassign appointments to attacker-controlled accounts, and extract management hashes for further actions like cancellation or rescheduling. This vulnerability poses a significant risk to organizations using the platform for scheduling, as it allows for unauthorized data access and the disruption of business operations through the manipulation of client information and schedules.

## Impact

Successful exploitation allows unauthenticated actors to read and modify sensitive booking data across the platform. This could result in data exfiltration of customer information, service disruption through mass appointment cancellation, or unauthorized scheduling changes, directly impacting the availability and integrity of the service for legitimate users.

## Recommendation

* Upgrade Easy!Appointments to a patched version beyond 1.6.0 immediately.
* Audit application access logs for recurring requests to the booking registration endpoint featuring sequentially incrementing ID parameters.
* Implement stricter server-side authorization checks for all appointment modification requests to ensure that 'manage_mode' flags are verified against server-stored session data rather than client-supplied input.
