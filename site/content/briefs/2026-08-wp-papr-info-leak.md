---
title: Sensitive Information Exposure in Page and Post Restriction WordPress Plugin
slug: 2026-08-wp-papr-info-leak
description: The Page and Post Restriction plugin for WordPress versions 1.4.0 and earlier fails to enforce global privacy settings on REST API endpoints, enabling unauthenticated access to restricted content.
date: "2026-08-05T09:15:51Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - Page and Post Restriction (<= 1.4.0)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The plugin's REST guards ... fail to consult the global toggles, making it possible for unauthenticated attackers to read the full rendered content of every published page and post.
    confidence_band: high
cves:
  - id: CVE-2026-12000
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12000
rules:
  - title: Detects CVE-2026-12000 Exploitation - Unauthenticated REST API Access to Posts/Pages
    description: Detects potential exploitation attempts by monitoring unauthenticated requests to the WordPress REST API endpoints which are known to be vulnerable to information exposure when global privacy settings are ignored.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1595
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Page and Post Restriction plugin to version > 1.4.0
      owner: IT Operations
      due: 48h
      evidence: Source document identifies version 1.4.0 as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Enable WAF rules for REST API endpoint access
      owner: IT Operations
      addresses: CVE-2026-12000
      evidence: Vulnerability exists in REST API endpoints.
---

The Page and Post Restriction plugin for WordPress (versions 1.4.0 and below) contains a critical logical flaw that results in sensitive information exposure. The vulnerability exists because the plugin's REST API protection mechanisms fail to verify the global security toggles intended to make all pages and posts private. While the plugin correctly restricts access via the frontend, the REST API guards only evaluate per-page/per-post metabox configurations. Consequently, global privacy settings ('Make all Pages Private' and 'Make all Posts Private') are ignored during REST API requests to /wp-json/wp/v2/pages and /wp-json/wp/v2/posts. An unauthenticated attacker can exploit this discrepancy to bypass intended access controls and retrieve the full content of any published post or page on an affected WordPress installation. This impact is significant for organizations relying on the plugin to protect private or sensitive internal content that would otherwise be exposed through the public-facing REST API.

## Impact

The vulnerability allows unauthenticated attackers to exfiltrate private post and page content, leading to unauthorized information disclosure. This bypasses the site's security policy, potentially exposing draft content, internal communications, or sensitive documentation intended only for authorized users. The scope of impact is contingent on the site administrator having enabled the 'Make all Pages Private' or 'Make all Posts Private' settings within the plugin.

## Recommendation

* Update the Page and Post Restriction plugin to a patched version beyond 1.4.0 immediately to restore REST API authorization logic.
* Audit web server logs for high-frequency requests to `/wp-json/wp/v2/posts/` and `/wp-json/wp/v2/pages/` from unauthenticated or suspicious external IP addresses.
* Consider disabling the WordPress REST API entirely if it is not required for site functionality, or implement a Web Application Firewall (WAF) rule to block unauthenticated access to these specific sensitive endpoints if remediation cannot be applied immediately.
