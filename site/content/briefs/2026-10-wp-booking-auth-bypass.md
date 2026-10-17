---
title: Authorization Bypass in WP Booking System - Booking Calendar
slug: 2026-10-wp-booking-auth-bypass
description: An authorization bypass vulnerability in the WP Booking System plugin allows authenticated subscribers to access sensitive booking email logs by manipulating request parameters, exposing PII.
date: "2026-10-17T04:48:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpbookingsystem:booking_calendar:*:*:*:*:*:wordpress:*:*
tags:
  - web-application-vulnerability
  - wordpress
  - cve-2026-108123
vendors:
  - WP Booking System
products:
  - WP Booking System – Booking Calendar (<= 2.1.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: By manipulating booking_id and email_log_id parameters, an authenticated Subscriber-level user can access and read sensitive notification emails.
    confidence_band: high
cves:
  - id: CVE-2026-108123
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108123
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch WP Booking System - Booking Calendar to a version beyond 2.1.0.3.
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies version 2.1.0.3 as the vulnerable baseline.
  hunt_leads:
    - lead: Monitor web access logs for repeated requests to wp-admin/profile.php involving consecutive booking_id or email_log_id integers.
      technique_id: T1592
      data_needed:
        - webserver log access
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The exploit relies on iterating booking_id and email_log_id.
---

The WP Booking System - Booking Calendar plugin for WordPress (versions 2.1.0.3 and earlier) contains an authorization bypass vulnerability (CVE-2026-108123) that allows authenticated users with Subscriber-level privileges to access restricted administrative data. The vulnerability exists because the plugin fails to properly verify user authorization before executing actions triggered by the admin_init hook on profile.php. By systematically iterating through booking_id and email_log_id parameters in requests to the plugin's internal endpoints, an attacker can retrieve the body content of stored notification emails. This exposure results in unauthorized access to sensitive customer PII, including names, email addresses, phone numbers, messages, and specific booking dates, which are intended to be accessible only by administrative users.

## Impact

Successful exploitation leads to a mass leak of customer PII stored within the plugin's email notification logs. This impacts WordPress sites utilizing the affected plugin version, potentially exposing data for every customer booking processed by the site. If exploited, an attacker could harvest significant volumes of contact information and booking details, leading to data privacy compliance violations and increased risk of follow-on social engineering or phishing attacks against the exposed individuals.

## Recommendation

1. Update the WP Booking System - Booking Calendar plugin to the latest version beyond 2.1.0.3 to remediate CVE-2026-108123.
2. Audit web server access logs for anomalous, sequential HTTP GET or POST requests directed at administrative pages (such as profile.php) that contain incrementing values in URL parameters like booking_id or email_log_id.
3. Implement strict access control lists (ACLs) on wp-admin pages if the plugin update cannot be applied immediately to mitigate unauthorized access by non-administrative users.
