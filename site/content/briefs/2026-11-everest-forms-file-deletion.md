---
brief_id: brief-2026-11-10-everest-forms-file-deletion
event_id: brief-2026-11-10-everest-forms-file-deletion
revision: 1
activity_at: "2026-11-10T08:05:07Z"
title: 'Everest Forms: Unauthenticated file deletion (CVE-2026-120513)'
slug: 2026-11-everest-forms-file-deletion
description: The Everest Forms WordPress plugin is vulnerable to unauthenticated file deletion in the wp-content/uploads directory due to insufficient input validation in the remove_csv_file_after_email_send function.
date: "2026-11-10T08:05:07Z"
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
cpes:
  - cpe:2.3:a:wpeverest:everest_forms:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - webserver
  - cve-2026-120513
vendors:
  - WPEverest
products:
  - Everest Forms – Contact Form, Payment Form, Quiz, Survey & Custom Form Builder with AI (<= 3.6.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This makes it possible for unauthenticated attackers to delete files within the wp-content/uploads directory on the server, which can lead to loss of uploaded content.
    confidence_band: high
cves:
  - id: CVE-2026-120513
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120513
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Everest Forms plugin to the latest version
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions up to and including 3.6.2
  hunt_leads:
    - lead: Monitor web server access logs for unusual POST requests targeting the Save-and-Continue or form-processing endpoints containing file path indicators
      technique_id: T1485
      data_needed:
        - webserver logs (cs-uri-stem, cs-method)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attack is triggered via insufficient file path validation in remove_csv_file_after_email_send
  mitigation_plan:
    - priority: immediate
      action: Disable Save-and-Continue addon or the affected form setting
      owner: IT Operations
      addresses: CVE-2026-120513
      evidence: The attack is only possible when the Save-and-Continue addon is active and Disable storing entry information is enabled
---

The Everest Forms plugin (up to version 3.6.2) for WordPress contains a file deletion vulnerability within the remove_csv_file_after_email_send function. An unauthenticated attacker can delete files in the wp-content/uploads directory when the Save-and-Continue addon is active and the "Disable storing entry information" setting is enabled on a specific form. If the deleted file is an .htaccess file, this may permit PHP execution in the uploads directory on affected Apache servers. In limited circumstances, the vulnerability may allow for file deletion outside of the uploads directory.

## Impact
The vulnerability allows unauthorized deletion of files, potentially leading to data loss. Security configuration bypass may occur if an .htaccess file controlling security in the uploads directory is removed, enabling PHP execution of uploaded scripts.

## Recommendation
- Upgrade the Everest Forms plugin to a version later than 3.6.2 immediately.
- Audit the WordPress uploads directory for unexpected deletion events or missing .htaccess files.
- Disable the "Save-and-Continue" addon if it is not required until the plugin can be patched.
- Verify that file system permissions prevent the web server user from deleting critical system files outside of the defined uploads directory.
