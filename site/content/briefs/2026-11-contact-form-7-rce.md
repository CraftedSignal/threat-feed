---
brief_id: brief-2026-11-09-contact-form-7-rce
event_id: brief-2026-11-09-contact-form-7-rce
revision: 1
activity_at: "2026-11-09T03:24:15Z"
title: 'Contact Form 7: Arbitrary file upload remote code execution (CVE-2026-114432)'
slug: 2026-11-contact-form-7-rce
description: The Contact Form 7 WordPress plugin before version 6.2.4 contains an arbitrary file upload vulnerability that allows unauthenticated attackers to write files to the server and potentially execute code via improperly configured PHP handlers.
date: "2026-11-09T03:24:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:contact_form_7:contact_form_7:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - rce
  - file-upload
  - vulnerability
products:
  - Contact Form 7 (< 6.2.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Contact Form 7 WordPress plugin before 6.2.4 does not validate the type or extension of files uploaded through a form file field.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: On a stock Debian or Ubuntu Apache configuration... the stored file can be located and executed, leading to Remote Code Execution.
    confidence_band: high
cves:
  - id: CVE-2026-114432
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114432
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Contact Form 7 to version 6.2.4 or later
      owner: IT Operations
      due: 24h
      evidence: The Contact Form 7 WordPress plugin before 6.2.4 does not validate the type or extension of files uploaded.
  hunt_leads:
    - lead: Identify suspicious file creation in WordPress upload directories
      technique_id: T1190
      data_needed:
        - Web server access logs
        - File integrity monitoring logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The flaw... allows unauthenticated users to upload arbitrary files to the site.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Contact Form 7 to 6.2.4 or later
      owner: IT Operations
      addresses: CVE-2026-114432
      evidence: Plugin version 6.2.4 addresses the vulnerability.
---

The Contact Form 7 WordPress plugin version 6.2.4 addresses a critical vulnerability (CVE-2026-114432) stemming from insufficient validation of file types and extensions during the upload process. The plugin also fails to properly remove temporary files, allowing them to persist on the server. On default Debian or Ubuntu Apache configurations where directory listing is enabled and .phar files are processed as PHP, an attacker can upload and execute malicious scripts. In other configurations, the flaw enables the storage of arbitrary content, such as HTML or SVG, in the web uploads directory, potentially facilitating cross-site scripting or other web-based attacks.

## Impact

Successful exploitation allows unauthenticated remote attackers to upload arbitrary files to a vulnerable server. Depending on server configuration, this can lead to Remote Code Execution (RCE) or the hosting of malicious active content served from the site's own origin.

## Recommendation

* Update the Contact Form 7 plugin to version 6.2.4 or later immediately.
* Audit the web server configuration to disable directory listing for public upload directories.
* Review server-side MIME type handling and PHP interpreter mappings to ensure only intended extensions are executed.
* Use the hunt lead below to identify potential attempts to upload or access suspicious file types in web-accessible directories.
