---
title: Arbitrary File Deletion in VikAppointments Services Booking Calendar
slug: 2026-10-vikappointments-file-deletion
description: The VikAppointments Services Booking Calendar plugin for WordPress is vulnerable to unauthenticated arbitrary file deletion via insufficient path validation in the extract function, which can lead to remote code execution.
date: "2026-10-03T08:54:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vikwp:vikappointments_services_booking_calendar:*:*:*:*:*:*:*:*
tags:
  - web-application
  - wordpress
  - vulnerability
  - file-deletion
vendors:
  - VikWP
products:
  - VikAppointments Services Booking Calendar (<= 1.2.21)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to delete arbitrary files on the server
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: which can easily lead to remote code execution when the right file is deleted
    confidence_band: high
cves:
  - id: CVE-2026-87115
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87115
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade VikAppointments Services Booking Calendar to a version greater than 1.2.21.
      owner: IT Operations
      due: 24h
      evidence: Source states all versions up to and including 1.2.21 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Remove or disable any 'File-type' custom fields from confirmation page shortcodes.
      owner: IT Operations
      addresses: CVE-2026-87115
      evidence: Exploitation requires at least one File-type custom field to be published on the confirmation page shortcode.
---

The VikAppointments Services Booking Calendar plugin for WordPress (all versions up to and including 1.2.21) contains a critical arbitrary file deletion vulnerability. The flaw originates in the plugin's 'extract' function, which performs insufficient validation on file paths. An unauthenticated attacker can exploit this weakness by submitting malicious input to delete arbitrary files on the web server hosting the WordPress site. 

This vulnerability poses a severe risk, as the deletion of critical system or application files, such as 'wp-config.php', can force a site reconfiguration or lead to remote code execution (RCE). Successful exploitation is specifically gated by the presence of a 'File-type' custom field on a published confirmation page shortcode, a configuration that is not default but can be manually implemented by administrators. Given the prevalence of WordPress and the potential for total system compromise, immediate remediation is required.

## Impact

Successful exploitation allows unauthenticated attackers to delete arbitrary files on the underlying web server. By targeting core WordPress files like 'wp-config.php', attackers can force the application to restart the installation process or access unauthorized data, ultimately facilitating remote code execution and full site takeover.

## Recommendation

* Update the VikAppointments Services Booking Calendar plugin to the latest version, ensuring all instances are beyond 1.2.21.
* Audit WordPress installations for the presence of the 'File-type' custom field within booking confirmation page shortcodes.
* If updating is not immediately possible, disable the use of custom 'File-type' fields in booking configurations until a patch can be applied.
* Review web server logs for HTTP POST requests targeting the plugin's booking submission endpoints containing suspicious directory traversal sequences (e.g., ../, ..\).
