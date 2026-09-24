---
title: Unauthenticated Path Traversal in eesy_ID2WP WordPress Plugin
slug: 2026-09-eesy-id2wp-path-traversal
description: The eesy_ID2WP WordPress plugin contains a path traversal vulnerability (CVE-2026-77193) via the id2wp_path parameter, allowing unauthenticated attackers to read arbitrary files from the hosting server.
date: "2026-09-24T10:46:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:eesy:eesy_id2wp_publish_indesign_html5:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - wordpress
  - cve
vendors:
  - eesy
products:
  - eesy_ID2WP – Publish InDesign HTML5 (<= 1.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The eesy_ID2WP – Publish InDesign HTML5 plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.0.3 via the id2wp_path parameter.
    confidence_band: high
cves:
  - id: CVE-2026-77193
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77193
rules:
  - title: Detects CVE-2026-77193 Exploitation - Path Traversal in eesy_ID2WP
    description: Detects exploitation attempts against CVE-2026-77193 by monitoring for path traversal sequences within the id2wp_path parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update eesy_ID2WP plugin to a version higher than 1.0.3
      owner: IT Operations
      due: 48h
      evidence: NVD vulnerability notice
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rule to block path traversal in id2wp_path parameter
      owner: IT Operations
      addresses: CVE-2026-77193
      evidence: NVD vulnerability notice
---

The eesy_ID2WP - Publish InDesign HTML5 plugin for WordPress is vulnerable to a path traversal vulnerability (CVE-2026-77193) affecting all versions up to and including 1.0.3. The vulnerability exists within the 'id2wp_path' parameter, which fails to properly sanitize user-provided input before using it to access files on the underlying server filesystem. An unauthenticated attacker can exploit this flaw by submitting crafted requests to the plugin to traverse directory structures, potentially reading sensitive configuration files, system files, or application source code. This vulnerability poses a significant risk to the confidentiality of the affected WordPress environment.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files on the web server. Depending on server configuration and file permissions, this can lead to the exposure of sensitive data including database credentials, wp-config.php files, system environment variables, and site content.

## Recommendation

- Update the eesy_ID2WP plugin to a version beyond 1.0.3 immediately.
- Implement Web Application Firewall (WAF) rules to inspect the 'id2wp_path' parameter for directory traversal sequences such as '../' or '..%2f'.
- Audit web server access logs for requests containing suspicious path traversal patterns targeting the plugin's endpoints.
