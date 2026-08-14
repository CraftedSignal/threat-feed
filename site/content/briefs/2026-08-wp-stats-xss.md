---
title: Stored Cross-Site Scripting in WP-Stats WordPress Plugin
slug: 2026-08-wp-stats-xss
description: The WP-Stats plugin for WordPress is vulnerable to Stored Cross-Site Scripting (CVE-2026-19794), allowing unauthenticated attackers to inject malicious scripts into pages due to insufficient sanitization.
date: "2026-08-14T10:07:25Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - gamerz
products:
  - WP-Stats
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The WP-Stats plugin for WordPress is vulnerable to Stored Cross-Site Scripting... making it possible for unauthenticated attackers to inject arbitrary web scripts.
    confidence_band: high
cves:
  - id: CVE-2026-19794
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19794
  - https://patchstack.com/database/wordpress/plugin/wp-stats/vulnerability/wordpress-wp-stats-plugin-2-56-cross-site-scripting-xss-vulnerability
rules:
  - title: Detect CVE-2026-19794 Exploitation - Stored XSS in WP-Stats
    description: Detects potential exploitation attempts by identifying common XSS payload signatures in HTTP POST/GET requests targeting WordPress plugin endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update WP-Stats plugin to patched version
      owner: IT Operations
      due: 24h
      evidence: Plugin is vulnerable in all versions up to and including 2.56.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to filter common XSS patterns in plugin requests
      owner: IT Operations
      addresses: CVE-2026-19794
      evidence: Plugin lacks sufficient input sanitization.
---

The WP-Stats plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 2.56. The vulnerability arises from insufficient input sanitization and output escaping mechanisms within the plugin. This flaw permits unauthenticated attackers to inject arbitrary malicious web scripts into stored pages within the WordPress site. Once injected, these scripts execute within the context of the user's browser whenever they view the compromised page. This vulnerability poses a significant risk for session hijacking, unauthorized administrative actions, or credential theft, particularly if an administrator views the injected content.

## Impact

Successful exploitation allows unauthenticated attackers to perform actions on behalf of authenticated users, potentially leading to full site compromise if an administrator interacts with the malicious payload. This vulnerability is classified as High severity with a CVSS 3.1 base score of 7.2. All WordPress environments running WP-Stats version 2.56 or lower are at risk until the plugin is updated to a patched version.

## Recommendation

- Immediately update the WP-Stats plugin to the latest version available that remediates CVE-2026-19794.
- Implement a Content Security Policy (CSP) to restrict the execution of unauthorized scripts and mitigate the impact of stored XSS.
- Deploy the Sigma rule provided below to monitor web server logs for suspicious payload patterns typically associated with script injection attempts.
- Conduct a post-remediation audit of stored plugin content to identify and remove any existing malicious scripts injected during the period of vulnerability.
