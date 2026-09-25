---
title: CVE-2026-93399 - IDOR Vulnerability in Bookly WordPress Plugin
slug: 2026-09-bookly-idor
description: The Bookly WordPress plugin up to version 28.2 contains multiple IDOR vulnerabilities in AJAX handlers allowing unauthenticated attackers to access customer data and delete arbitrary appointments.
date: "2026-09-25T10:52:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bookly:bookly:*:*:*:*:*:wordpress:*:*
vendors:
  - Bookly
products:
  - Bookly (<= 28.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Bookly plugin for WordPress is vulnerable to Insecure Direct Object Reference in versions up to, and including, 28.2 via the AJAX actions.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This makes it possible for unauthenticated attackers to enumerate sequential order IDs, disclose other customers' order tokens, retrieve calendar/appointment information.
    confidence_band: high
cves:
  - id: CVE-2026-93399
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93399
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Bookly plugin to the version containing the patch for CVE-2026-93399
      owner: IT Operations
      due: 24h
      evidence: Source documentation of CVE-2026-93399
  hunt_leads:
    - lead: Identify spikes in HTTP POST traffic to /wp-admin/admin-ajax.php involving Bookly-related parameters
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation of AJAX handlers for data enumeration
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest version of Bookly
      owner: IT Operations
      addresses: CVE-2026-93399
      evidence: NVD vulnerability disclosure
---

The Bookly plugin for WordPress is vulnerable to Insecure Direct Object Reference (IDOR) exploitation in versions 28.2 and earlier. The vulnerability stems from improper validation within several AJAX handlers, specifically 'bookly_get_form_id', 'bookly_render_complete', 'bookly_add_to_calendar', and 'bookly_rollback_order'. 

The 'bookly_get_form_id' handler accepts an attacker-supplied 'order_id' from user-submitted form data and stores it in the booking session without verification. Subsequent handlers, such as 'bookly_render_complete', trust this session-stored ID to look up and return sensitive order tokens. This flaw enables unauthenticated attackers to enumerate sequential order IDs, leading to the unauthorized disclosure of customer order tokens and appointment details. Furthermore, the 'bookly_rollback_order' handler allows attackers to permanently delete arbitrary non-completed bookings, which triggers cascading deletions of associated customer appointment records. This vulnerability poses a significant risk to data privacy and service integrity for organizations utilizing the Bookly plugin.
