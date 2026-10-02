---
title: Stored Cross-Site Scripting in JetAppointment Plugin for WordPress
slug: 2026-10-jetappointment-xss
description: An unauthenticated stored XSS vulnerability in the JetAppointment WordPress plugin allows attackers to inject malicious scripts via the friendlyTime parameter that execute in an administrator's browser context.
date: "2026-10-02T14:25:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:crocoblock:jetappointment:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-application
  - wordpress
  - cve-2026-93875
vendors:
  - Crocoblock
products:
  - JetAppointment (<= 2.5.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: The injected payload is stored in the wp_jet_appointments_meta table via the unauthenticated jet_engine_form_booking_submit endpoint and executes in the administrator's browser.
    confidence_band: med
cves:
  - id: CVE-2026-93875
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93875
rules:
  - title: Detect CVE-2026-93875 Exploitation - Stored XSS Attempt in JetAppointment
    description: Detects exploitation attempts against the JetAppointment plugin by identifying POST requests to the submission endpoint containing script tags in the friendlyTime parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch JetAppointment to a version > 2.5.2.1.
      owner: IT Operations
      due: 48h
      evidence: Source states all versions up to and including 2.5.2.1 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rule to filter malicious scripts in the friendlyTime parameter.
      owner: Security Engineering
      addresses: CVE-2026-93875
      evidence: Input sanitization flaw identified in the friendlyTime parameter.
---

The JetAppointment plugin for WordPress, developed by Crocoblock, is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 2.5.2.1. The flaw exists due to insufficient input sanitization and output escaping within the 'friendlyTime' parameter. An unauthenticated attacker can exploit this by sending a crafted HTTP POST request to the 'jet_engine_form_booking_submit' endpoint. The malicious payload is subsequently stored in the 'wp_jet_appointments_meta' database table. The payload executes in the browser of an administrator who views the appointment details within the WordPress admin dashboard, potentially leading to unauthorized administrative actions or session compromise.

## Attack Chain

1. An attacker identifies the target WordPress site running a vulnerable version of JetAppointment.
2. The attacker crafts a malicious HTTP POST request targeting the 'jet_engine_form_booking_submit' endpoint.
3. The attacker includes a JavaScript payload within the 'friendlyTime' parameter of the request body.
4. The plugin fails to sanitize the input and saves the payload directly into the 'wp_jet_appointments_meta' table in the WordPress database.
5. An administrator logs into the WordPress dashboard and navigates to the appointment management section.
6. The plugin retrieves the malicious record and renders it in the appointment details popup.
7. The administrator's browser executes the stored JavaScript, enabling further malicious activity such as account creation or privilege escalation.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a WordPress administrator's session. This could result in the unauthorized creation of administrative accounts, modification of site content, or the exfiltration of sensitive site configuration data. The vulnerability affects all users running JetAppointment version 2.5.2.1 or earlier.

## Recommendation

Prioritized, concrete actions for detection engineering and security operations teams:
- Update the JetAppointment plugin to a patched version beyond 2.5.2.1 as soon as an update becomes available.
- Implement a Web Application Firewall (WAF) rule to block POST requests to 'jet_engine_form_booking_submit' that contain script tags or suspicious JavaScript patterns in the 'friendlyTime' parameter.
- Monitor web server access logs for anomalous POST activity to 'jet_engine_form_booking_submit' from external IP addresses.
