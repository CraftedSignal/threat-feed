---
title: Information Disclosure Vulnerability in Royal Elementor Addons
slug: 2026-09-royal-elementor-info-disclosure
description: An improper access control vulnerability in the Royal Elementor Addons plugin for WordPress allows unauthenticated remote attackers to disclose sensitive configuration or user information via REST API endpoints.
date: "2026-09-14T13:02:45Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:netgear:dg834gv5_firmware:1.6.01.34:*:*:*:*:*:*:*
vendors:
  - WP Royal
products:
  - Royal Elementor Addons (< 1.3.79)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A vulnerability in the Royal Elementor Addons plugin for WordPress allows an unauthenticated remote attacker to perform information disclosure.
    confidence_band: high
cves:
  - id: CVE-2024-4235
    cvss: 2.7
    epss: 0.00557
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3344
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Royal Elementor Addons plugin to version 1.3.79 or later
      owner: IT Operations
      due: 24h
      evidence: Vendor advisory fix version
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Royal Elementor Addons 1.3.79
      owner: IT Operations
      addresses: CVE-2024-4235
      evidence: Source advisory
---

The Royal Elementor Addons plugin for WordPress contains an information disclosure vulnerability, identified as CVE-2024-4235. This vulnerability stems from improper access control checks within the plugin's REST API endpoints. An unauthenticated remote attacker can exploit this flaw by sending specifically crafted HTTP requests to these endpoints, potentially resulting in the unauthorized access to sensitive plugin configurations, site metadata, or user-related information. The vulnerability affects versions of the Royal Elementor Addons plugin prior to 1.3.79. Given the widespread use of Elementor addons in the WordPress ecosystem, defenders should audit web server logs for unauthorized access patterns directed at the plugin's API paths and prioritize patching to the latest version to remediate the flaw.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to exfiltrate sensitive site configuration details or user data, which could facilitate further reconnaissance or account takeover attacks. While the exact scope of accessible data depends on the specific site configuration, such information leaks often lead to the exposure of backend paths, plugin settings, or administrative metadata.

## Recommendation

Prioritize the update of the Royal Elementor Addons plugin to version 1.3.79 or later across all WordPress deployments immediately. Detection engineers should inspect web server access logs for anomalous GET requests directed at REST API routes associated with the plugin that return 200 OK statuses from unauthenticated sources.
