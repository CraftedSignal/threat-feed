---
brief_id: brief-2026-10-31-wp-directory-kit
event_id: brief-2026-10-31-wp-directory-kit
revision: 1
activity_at: "2026-10-31T11:57:34Z"
title: 'WP Directory Kit: SQL injection in idfield parameter (CVE-2026-109197)'
slug: 2026-10-wp-directory-kit
description: The WP Directory Kit WordPress plugin is vulnerable to unauthenticated SQL injection via the idfield parameter due to insufficient input sanitization, enabling potential data exfiltration.
date: "2026-10-31T11:57:34Z"
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
  validation_status: Source-confirmed vulnerability details; environment validation required to confirm plugin presence and patching status.
cpes:
  - cpe:2.3:a:wp_directory_kit_project:wp_directory_kit:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - sql-injection
  - web-application
products:
  - WP Directory Kit (<= 1.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries
    confidence_band: high
cves:
  - id: CVE-2026-109197
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109197
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and disable vulnerable WP Directory Kit plugin versions (<= 1.6.0) across all web assets.
      owner: IT Operations
      due: 24h
      evidence: Vulnerable plugin version <= 1.6.0
  hunt_leads:
    - lead: Monitor web server logs for requests to site paths containing the idfield parameter with SQL injection syntax (e.g., UNION, SELECT, OR 1=1).
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-uri-query, cs-uri-stem)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability exists via the idfield parameter.
  mitigation_plan:
    - priority: immediate
      action: Deactivate the WP Directory Kit plugin until a vendor patch is provided.
      owner: IT Operations
      addresses: CVE-2026-109197
      evidence: Plugin vulnerable up to and including 1.6.0
---

The WP Directory Kit plugin for WordPress (all versions up to and including 1.6.0) contains a vulnerability that allows unauthenticated SQL injection. The flaw exists in the 'idfield' parameter, where user-supplied input is not properly escaped before being included in a SQL query. This failure to use prepared statements allows attackers to inject arbitrary SQL commands.

## Impact
Successful exploitation allows unauthenticated attackers to append malicious SQL commands to existing queries, which can be leveraged to extract sensitive information from the underlying database.

## Recommendation
- Inventory all WordPress installations to identify instances of the WP Directory Kit plugin.
- Disable or remove the plugin until a patch is released by the vendor, as no fixed version is currently specified in the source.
- Review web server access logs for requests containing SQL injection patterns directed at common WordPress plugin paths and query parameters.
