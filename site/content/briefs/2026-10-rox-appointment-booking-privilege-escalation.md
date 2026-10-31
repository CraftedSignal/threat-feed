---
brief_id: brief-2026-10-31-rox-appointment-booking-privilege-escalation
event_id: brief-2026-10-31-rox-appointment-booking-privilege-escalation
revision: 1
activity_at: "2026-10-31T09:55:10Z"
title: 'Rox Appointment Booking: Privilege Escalation (CVE-2026-104012)'
slug: 2026-10-rox-appointment-booking-privilege-escalation
description: The Rox Appointment Booking plugin for WordPress is vulnerable to unauthenticated mass assignment, allowing attackers to overwrite administrator email addresses and facilitate account takeover.
date: "2026-10-31T09:55:10Z"
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
  validation_status: Verified against NVD vulnerability metadata.
cpes:
  - cpe:2.3:a:rox:appointment_booking:*:*:*:*:*:wordpress:*:*
vendors:
  - Rox
products:
  - Rox Appointment Booking – Appointment Booking Scheduling Solution (<= 1.3.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability allows an unauthenticated attacker to persist an arbitrary WordPress user ID... allowing full account takeover.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: enabling full account takeover via a standard WordPress password-reset request.
    confidence_band: high
cves:
  - id: CVE-2026-104012
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104012
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Rox Appointment Booking plugin to the latest patched version.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 1.3.1.
  hunt_leads:
    - lead: Search web server logs for HTTP POST requests to the plugin API endpoint.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The public /rox-appointment-booking/v1/public/booking REST endpoint is the entry point for the exploit.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to a version released after October 2026.
      owner: IT Operations
      addresses: CVE-2026-104012
      evidence: Plugin vulnerable up to version 1.3.1.
---

The Rox Appointment Booking plugin for WordPress (versions 1.3.1 and earlier) contains a critical mass assignment vulnerability in the '/rox-appointment-booking/v1/public/booking' REST endpoint. An unauthenticated attacker can inject arbitrary data into the 'wp_user_id' field of a customer record. A subsequent administrative action - viewing and saving the record - triggers an unauthorized email update for the administrator, enabling a password reset attack.

## Attack Chain

1. Attacker identifies a WordPress site running the vulnerable Rox Appointment Booking plugin.
2. Attacker sends a crafted HTTP POST request to '/rox-appointment-booking/v1/public/booking'.
3. The plugin executes mass assignment, allowing the attacker to store an arbitrary 'wp_user_id' in a new customer row.
4. An administrator logs into the WordPress dashboard and accesses the appointment management interface.
5. The administrator views the malicious customer record and clicks "Update Customer".
6. The plugin logic 'SaveCustomer::handleRequest()' updates the targeted administrator's email address in the WordPress database.
7. Attacker initiates a standard password reset request for the compromised administrator account.

## Impact

Successful exploitation leads to full administrator account takeover. The attacker gains administrative access to the WordPress instance, which can be leveraged for further persistence, data exfiltration, or secondary malware distribution.

## Recommendation

* Update the "Rox Appointment Booking - Appointment Booking Scheduling Solution" plugin to the latest version immediately.
* Review administrative user records for unauthorized email address changes.
* Audit the '/rox-appointment-booking/v1/public/booking' endpoint access logs for anomalous POST requests containing unexpected JSON fields.
