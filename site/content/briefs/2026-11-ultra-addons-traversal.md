---
brief_id: brief-2026-11-10-ultra-addons-traversal
event_id: brief-2026-11-10-ultra-addons-traversal
revision: 1
activity_at: "2026-11-10T08:05:01Z"
title: 'Ultra Addons for Contact Form 7: Directory Traversal (CVE-2026-100386)'
slug: 2026-11-ultra-addons-traversal
description: The Ultra Addons for Contact Form 7 WordPress plugin is vulnerable to directory traversal via the uacf7_wpcf7_mail_components function, allowing unauthenticated file disclosure when specific PDF generation features are enabled.
date: "2026-11-10T08:05:01Z"
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
  validation_status: Source verified; no IOCs or specific request paths documented for rule generation.
cpes:
  - cpe:2.3:a:ultra_addons:for_contact_form_7:*:*:*:*:*:*:*:*
tags:
  - web-application
  - wordpress
  - vulnerability
  - directory-traversal
vendors:
  - Ultra Addons
products:
  - Ultra Addons for Contact Form 7 (<= 3.5.54)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to Directory Traversal in all versions up to, and including, 3.5.54
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server
    confidence_band: high
cves:
  - id: CVE-2026-100386
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100386
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Ultra Addons for Contact Form 7 to a version beyond 3.5.54
      owner: IT Operations
      due: 48h
      evidence: Vulnerability exists in 3.5.54 and below
  hunt_leads:
    - lead: Identify and analyze HTTP requests containing path traversal sequences (../) targeting plugin-specific parameters
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is a directory traversal flaw in a plugin function
  mitigation_plan:
    - priority: immediate
      action: Disable PDF Generator addon or remove PDF body templates
      owner: IT Operations
      addresses: CVE-2026-100386
      evidence: Exploitation requires the PDF Generator addon to be active and an administrator-configured PDF body template to be enabled
---

The Ultra Addons for Contact Form 7 plugin for WordPress contains a directory traversal vulnerability in versions 3.5.54 and earlier. The flaw exists within the uacf7_wpcf7_mail_components function. Unauthenticated attackers can leverage this to read arbitrary files on the web server. Exploitation is contingent upon the PDF Generator addon being active and an administrator having configured a PDF body template for a specific contact form.

## Impact

Successful exploitation allows unauthenticated remote attackers to read arbitrary files from the server filesystem, potentially leading to the disclosure of sensitive information such as configuration files, environment secrets, or system credentials.

## Recommendation

* Inventory WordPress installations running the "Ultra Addons for Contact Form 7" plugin to identify versions 3.5.54 or older.
* Update the plugin to a version released after 3.5.54 that addresses this vulnerability.
* If updating is not immediately possible, disable the PDF Generator addon or remove any active PDF body templates for contact forms as a temporary mitigation.
* Audit web server access logs for anomalous requests to the WordPress plugins directory or patterns indicative of directory traversal (e.g., "../") targeting plugin-specific parameters.
