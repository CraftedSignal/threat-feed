---
brief_id: brief-2026-11-15-webtoffee-ssrf
event_id: brief-2026-11-15-webtoffee-ssrf
revision: 1
activity_at: "2026-11-15T17:04:41Z"
title: 'WebToffee Product Import Export for WooCommerce: Server-Side Request Forgery (CVE-2026-118989)'
slug: 2026-11-webtoffee-ssrf
description: An authenticated server-side request forgery (SSRF) vulnerability in the WebToffee Product Import Export for WooCommerce plugin allows shop_manager users to exfiltrate data from internal services by bypassing redirect validation.
date: "2026-11-15T17:04:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Vulnerability details and fixed version verified against CVE Program and source.
cpes:
  - cpe:2.3:a:webtoffee:product_import_export_for_woocommerce:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=1C7664EB-FFD1-5477-B01E-6CE3A616859A&utm_source=rss&utm_medium=rss
tags:
  - ssrf
  - wordpress
  - web-application
  - vulnerability
vendors:
  - WebToffee
products:
  - Product Import Export for WooCommerce
product_versions:
  - product: Product Import Export for WooCommerce
    range: < 2.6.8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: WebToffee Product Import Export for WooCommerce 2.5.1 before 2.6.8 contains a server-side request forgery vulnerability in download_remote_file that allows shop_manager users to reach internal services via redirects.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: In the lab, a mock metadata service's credentials were returned to the attacker.
    confidence_band: high
cves:
  - id: CVE-2025-1912
    kev_status: "false"
  - id: CVE-2026-118989
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2025-1912
  - https://cveawg.mitre.org/api/cve/CVE-2026-118989
  - https://sploitus.com/exploit?id=1C7664EB-FFD1-5477-B01E-6CE3A616859A
  - https://sploitus.com/exploit?id=1C7664EB-FFD1-5477-B01E-6CE3A616859A&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update 'Product Import Export for WooCommerce' plugin to version 2.6.8 or later.
      owner: IT Operations
      due: 48h
      evidence: Fixed in 2.6.8
  hunt_leads:
    - lead: Monitor web server access logs for anomalous requests to /wp-admin/admin-ajax.php involving 'iew_import_ajax_basic' action and high-frequency 'validate_file' or 'get_steps' calls.
      technique_id: T1190
      data_needed:
        - web server logs (cs-uri-stem, cs-uri-query, user_id)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The import process uses AJAX calls to perform the SSRF.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2.6.8 or later.
      owner: IT Operations
      addresses: CVE-2026-118989
      evidence: Fixed in 2.6.8
---

## Overview
WebToffee Product Import Export for WooCommerce versions prior to 2.6.8 contain a server-side request forgery (SSRF) vulnerability. An authenticated attacker with 'shop_manager' privileges can exploit the 'from URL' import feature to perform non-blind SSRF. The application follows HTTP redirects during the import process without re-validating the target host against private, link-local, or loopback network ranges. By supplying a URL that returns an HTTP 302 redirect, an attacker can force the server to fetch and return responses from internal resources, such as cloud metadata services.

## Attack Chain
1. Attacker authenticates as a user with 'shop_manager' permissions.
2. Attacker initiates a product import action using the 'from URL' method within the plugin.
3. Attacker provides a malicious URL designed to return an HTTP 302 redirect.
4. Plugin's `download_remote_file` function fetches the URL, following the redirect to an internal resource (e.g., 169.254.169.254).
5. Plugin retrieves the internal resource response and stores it as a temporary file.
6. Plugin returns the internal response data to the attacker through the column-mapping interface, allowing for unauthorized data access.

## Impact
Successful exploitation allows an authenticated user with limited privileges to access internal services and metadata, leading to potential credential exfiltration or unauthorized access to internal network information. This bypasses the remediation previously implemented for CVE-2025-1912.

## Recommendation
- Upgrade the WebToffee 'Product Import Export for WooCommerce' plugin to version 2.6.8 or later immediately.
- Review access control lists for 'shop_manager' roles to ensure the principle of least privilege is applied.
- Enforce IMDSv2 and restrict instance role permissions on cloud environments to mitigate the impact of SSRF against metadata services.
