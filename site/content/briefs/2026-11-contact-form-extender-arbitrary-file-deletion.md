---
brief_id: brief-2026-11-03-contact-form-extender-arbitrary-file-deletion
event_id: brief-2026-11-03-contact-form-extender-arbitrary-file-deletion
revision: 1
activity_at: "2026-11-03T05:54:50Z"
title: 'Contact Form Extender for Divi Builder: Arbitrary file deletion (CVE-2026-120559)'
slug: 2026-11-contact-form-extender-arbitrary-file-deletion
description: The Contact Form Extender for Divi Builder plugin for WordPress contains an arbitrary file deletion vulnerability in versions 1.0.6 and below that allows unauthenticated attackers to delete sensitive files via the cfefd_remove_uploaded_file function.
date: "2026-11-03T05:54:50Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:contact_form_extender_for_divi_builder_project:contact_form_extender_for_divi_builder:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - arbitrary-file-deletion
  - wordpress
vendors:
  - WordPress
products:
  - Contact Form Extender for Divi Builder (<= 1.0.6)
cves:
  - id: CVE-2026-120559
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120559
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit WordPress installations for the Contact Form Extender for Divi Builder plugin and disable/remove version 1.0.6 or lower.
      owner: IT Operations
      due: 24h
      evidence: The Contact Form Extender for Divi Builder plugin for WordPress is vulnerable to Arbitrary File Deletion... in all versions up to, and including, 1.0.6.
  hunt_leads:
    - lead: Hunt for unauthorized access to the AJAX endpoint used by the vulnerable function in web server access logs.
      technique_id: T1190
      data_needed:
        - Web server access logs (HTTP POST requests)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated attacker can retrieve the nonce... and trigger the function to delete sensitive server files.
  mitigation_plan:
    - priority: immediate
      action: Remove or disable the plugin until a vendor patch is applied.
      owner: IT Operations
      addresses: CVE-2026-120559
      evidence: The Contact Form Extender for Divi Builder plugin for WordPress is vulnerable to Arbitrary File Deletion... in all versions up to, and including, 1.0.6.
---

The Contact Form Extender for Divi Builder plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient path validation in the cfefd_remove_uploaded_file() function. The vulnerability affects all versions up to and including 1.0.6. An unauthenticated attacker can retrieve the nonce required for this AJAX action from the public page source, allowing them to delete arbitrary files on the server. Successful exploitation could lead to remote code execution by deleting critical configuration files like wp-config.php.

## Impact
Successful exploitation allows unauthenticated attackers to delete arbitrary files from the web server, potentially resulting in complete site compromise or remote code execution.

## Recommendation
1. Identify all WordPress installations running the "Contact Form Extender for Divi Builder" plugin.
2. Disable or remove the plugin until a patch is released by the developer.
3. Monitor web server access logs for anomalous POST requests targeting the AJAX endpoint associated with the cfefd_remove_uploaded_file function.
