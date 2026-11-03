---
brief_id: brief-2026-11-03-woo-shipment-sql-injection
event_id: brief-2026-11-03-woo-shipment-sql-injection
revision: 1
activity_at: "2026-11-03T05:54:45Z"
title: 'Advanced Shipment Tracking for WooCommerce: SQL injection (CVE-2026-120558)'
slug: 2026-11-woo-shipment-sql-injection
description: The Advanced Shipment Tracking for WooCommerce plugin for WordPress is vulnerable to authenticated SQL injection via the tracking_provider parameter, allowing attackers with Shop Manager privileges to exfiltrate database contents.
date: "2026-11-03T05:54:45Z"
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
  validation_status: Source identifies vulnerability and affected component clearly; environment validation required to confirm plugin version and access control configuration.
cpes:
  - cpe:2.3:a:woocommerce:advanced_shipment_tracking:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - sql-injection
  - webserver
vendors:
  - WooCommerce
products:
  - Advanced Shipment Tracking for WooCommerce (<= 3.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Advanced Shipment Tracking for WooCommerce plugin for WordPress is vulnerable to SQL Injection via the tracking_provider parameter of the POST /wp-json/wc-ast/v3/orders/<order_id>/shipment-trackings REST endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-120558
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120558
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit users with Shop Manager permissions and restrict access if unnecessary.
      owner: IT Operations
      due: 24h
      evidence: Exploitation requires authenticated access at the Shop Manager level.
  hunt_leads:
    - lead: Search web access logs for POST requests to /wp-json/wc-ast/v3/orders/ containing suspicious SQL characters (e.g., UNION, SELECT, --, ;) in the tracking_provider parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability manifests via malicious input to the tracking_provider parameter in a specific REST endpoint.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Advanced Shipment Tracking for WooCommerce to the latest version once a fix is released (superseding 3.9).
      owner: IT Operations
      addresses: CVE-2026-120558
      evidence: Plugin version 3.9 and earlier are affected.
---

The Advanced Shipment Tracking for WooCommerce plugin for WordPress is vulnerable to SQL injection in versions up to and including 3.9. The vulnerability exists within the WC_Advanced_Shipment_Tracking_Admin::get_provider_slug_from_name() method, where the tracking_provider parameter is improperly concatenated into a SQL query processed by $wpdb->prepare(). Authenticated users with Shop Manager privileges or higher can leverage this to execute unauthorized SQL queries and extract sensitive information from the database.

## Impact
Successful exploitation allows authenticated attackers to perform unauthorized database operations, potentially leading to the exfiltration of sensitive information contained within the WordPress database.

## Recommendation
- Update Advanced Shipment Tracking for WooCommerce to the version containing the security patch (expected to be > 3.9).
- Review Shop Manager role assignments and audit current plugin users for unauthorized account activity.
- Monitor REST API traffic targeting /wp-json/wc-ast/v3/orders/ for anomalous POST requests containing SQL syntax or characters commonly used in injection attacks.
