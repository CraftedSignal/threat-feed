---
brief_id: brief-2026-11-03-fluentcart-file-deletion
event_id: brief-2026-11-03-fluentcart-file-deletion
revision: 1
activity_at: "2026-11-03T05:55:04Z"
title: 'FluentCart: Arbitrary file deletion (CVE-2026-120577)'
slug: 2026-11-fluentcart-file-deletion
description: The FluentCart WordPress plugin contains an arbitrary file deletion vulnerability in the deleteFile function that allows authenticated attackers to delete sensitive server files, potentially leading to remote code execution.
date: "2026-11-03T05:55:04Z"
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
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:fluentcart:fluentcart:*:*:*:*:*:wordpress:*:*
vendors:
  - FluentCart
products:
  - FluentCart (<= 1.6.2)
cves:
  - id: CVE-2026-120577
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120577
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade FluentCart to a version exceeding 1.6.2
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions up to and including 1.6.2.
  hunt_leads:
    - lead: Identify authenticated users with custom-level roles performing administrative file operations.
      technique_id: T1059.003
      data_needed:
        - Web server access logs
        - WordPress plugin activity logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is exploitable by authenticated attackers with custom-level access and above.
  mitigation_plan:
    - priority: immediate
      action: Update FluentCart plugin to the version containing the patch for CVE-2026-120577.
      owner: IT Operations
      addresses: CVE-2026-120577
      evidence: Patch required to remediate insufficient file path validation.
---

The FluentCart plugin for WordPress (versions 1.6.2 and earlier) is susceptible to an arbitrary file deletion vulnerability. This flaw stems from improper file path validation within the plugin's `deleteFile` function. Authenticated users with custom-level access or higher can leverage this vulnerability to delete critical files on the web server, such as `wp-config.php`, which can result in application compromise or remote code execution.

## Impact
Successful exploitation allows for the deletion of arbitrary files on the hosting server. Deleting critical application configuration files, such as `wp-config.php`, may force the application into an installation state or facilitate further exploitation leading to remote code execution.

## Recommendation
- Update the FluentCart plugin to the latest available version (beyond 1.6.2) to remediate the path validation flaw.
- Review WordPress user role assignments to ensure that users with custom-level access and above are limited to trusted individuals.
- Audit web server file access logs for requests targeting the `deleteFile` function logic, typically associated with administrative or plugin-specific API endpoints.
