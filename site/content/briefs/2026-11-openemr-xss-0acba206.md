---
brief_id: brief-2026-11-08-openemr-xss-0acba206
event_id: brief-2026-11-08-openemr-xss-0acba206
revision: 1
activity_at: "2026-11-08T17:30:33Z"
title: 'OpenEMR: Stored Cross-Site Scripting (CVE-2026-124463)'
slug: 2026-11-openemr-xss-0acba206
description: OpenEMR versions prior to 8.3.0 contain a stored cross-site scripting vulnerability allowing authenticated users with CAMOS access to execute arbitrary scripts in a victim context.
date: "2026-11-08T17:30:33Z"
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
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-application
  - medical-software
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated users with CAMOS access can inject malicious HTML/scripts via the ajax_save.php script.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The payload executes in the victim's browser context when the stored content is accessed.
    confidence_band: high
cves:
  - id: CVE-2026-124463
    cvss: 8.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124463
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenEMR instances to version 8.3.0 or later.
      owner: IT Operations
      due: 72h
      evidence: Vulnerability remediation requires upgrading to the fixed version 8.3.0.
  hunt_leads:
    - lead: Identify users performing save operations via ajax_save.php containing script tags.
      technique_id: T1059.007
      data_needed:
        - Web server access logs (POST method to ajax_save.php)
        - Request bodies containing <script>, onload, or onerror tags
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers inject HTML by saving malicious CAMOS content through ajax_save.php.
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenEMR to version 8.3.0.
      owner: IT Operations
      addresses: CVE-2026-124463
      evidence: Vendor patch release 8.3.0 addresses the stored XSS vulnerability.
---

OpenEMR versions before 8.3.0 contain a stored cross-site scripting (XSS) vulnerability. Authenticated users with CAMOS (Computerized Assisted Medical Office Suite) access can inject malicious HTML or scripts by saving content through the `ajax_save.php` endpoint. The payload is subsequently executed when a victim accesses the entry via the `rx_print.php` script (specifically the non-print_html branch), allowing the attacker to perform actions or read data as the authenticated user.

## Impact
Successful exploitation allows authenticated attackers to perform unauthorized actions or exfiltrate sensitive data by executing scripts within the browser session of a victim user who views the malicious content.

## Recommendation
- Upgrade OpenEMR to version 8.3.0 or later to remediate the vulnerability.
- Audit access controls for the CAMOS module to ensure only trusted users have the ability to save content.
- Monitor web server logs for suspicious POST requests to `ajax_save.php` containing script-related characters.
