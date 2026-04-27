---
title: WordPress Create DB Tables Plugin Authorization Bypass Vulnerability (CVE-2026-4119)
slug: 2026-04-wordpress-create-db-tables-auth-bypass
description: The Create DB Tables plugin for WordPress versions 1.2.1 and earlier is vulnerable to an authorization bypass, allowing authenticated users to create and delete database tables without proper checks, potentially leading to complete site destruction.
date: "2026-04-22T09:16:49Z"
severities:
  - critical
tags:
  - wordpress
  - authorization-bypass
  - plugin-vulnerability
  - cve-2026-4119
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-4119
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4119
rules:
  - title: Detect Unauthorized DB Table Modification
    description: Detects POST requests to wp-admin/admin-post.php with actions related to database table manipulation, indicating potential unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: WAF - Block Unauthorized DB Table Modification
    description: This rule detects and blocks POST requests to wp-admin/admin-post.php with actions related to database table manipulation if not originating from an admin IP address.
    platform: sigma
    severity: critical
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - firewall
      - linux
rules_count: 2
---

The Create DB Tables plugin, versions 1.2.1 and earlier, suffers from an authorization bypass vulnerability (CVE-2026-4119). This flaw stems from the plugin's failure to implement capability checks or nonce verification for its admin_post action hooks, specifically those responsible for creating (admin_post_add_table) and deleting (admin_post_delete_db_table) database tables. Because the admin_post hook only requires a user to be logged in, any authenticated user, including those with the…
