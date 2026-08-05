---
title: Arbitrary File Deletion in Content Egg Plugin for WordPress
slug: 2026-08-content-egg-traversal
description: The Content Egg plugin for WordPress is vulnerable to a path traversal flaw in the 'img_file' parameter, allowing authenticated attackers with author-level permissions to delete arbitrary files on the web server.
date: "2026-08-05T15:20:32Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - WordPress
products:
  - Content Egg – Affiliate Product Importer & Price Comparison (<= 11.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated attacker, with author-level access and above, to delete arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This makes it possible for authenticated attackers, with author-level access and above, to delete arbitrary files on the affected site's server.
    confidence_band: high
cves:
  - id: CVE-2026-15979
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15979
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Content Egg plugin to version 11.3.1 or higher
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-15979 remediation requirements
  mitigation_plan:
    - priority: immediate
      action: Monitor/Restrict WordPress author-level account activity and file-deletion related API calls
      owner: Security Operations
      addresses: CVE-2026-15979
      evidence: Source identification of author-level access as the exploitation vector
---

The Content Egg plugin for WordPress, a popular affiliate marketing and price comparison tool, contains a critical path traversal vulnerability (CVE-2026-15979) in versions 11.3.0 and earlier. The flaw resides in the handling of the 'img_file' field within 'cegg_data' post metadata. The plugin performs insufficient input sanitization, passing the user-provided value through 'wp_strip_all_tags()' - which fails to remove path traversal sequences - before storing it in the database. When the 'getFullImgPath()' function is called, the tainted string is concatenated into a filesystem path and passed directly to the PHP 'unlink()' function. An authenticated attacker with author-level access or higher can exploit this to delete arbitrary files, potentially leading to a denial of service or creating conditions conducive to remote code execution by removing critical application configuration or core system files.

## Impact

Successful exploitation allows for the deletion of arbitrary files on the underlying web server hosting the WordPress site. Depending on the targeted file, this can result in total site compromise, loss of data, or disruption of service. There are no reports of widespread active exploitation, but the vulnerability's impact score of 8.1 (CVSS v3.1) highlights its severity for enterprise environments relying on the WordPress plugin ecosystem.

## Recommendation

- Update the Content Egg plugin to version 11.3.1 or later immediately, as identified in the vendor security documentation for CVE-2026-15979.
- Audit logs for unauthorized modifications to 'cegg_data' post metadata by low-privileged user accounts.
- Implement a web application firewall (WAF) rule to block POST requests containing path traversal sequences (e.g., '../') in the 'img_file' parameter of WordPress meta-data submissions.
