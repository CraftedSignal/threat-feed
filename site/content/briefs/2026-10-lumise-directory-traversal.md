---
brief_id: brief-2026-10-28-lumise-directory-traversal
event_id: brief-2026-10-28-lumise-directory-traversal
revision: 1
activity_at: "2026-10-28T08:26:55Z"
title: 'Product Designer for WooCommerce: Arbitrary file read via directory traversal (CVE-2026-15323)'
slug: 2026-10-lumise-directory-traversal
description: The Product Designer for WooCommerce plugin (<= 2.1.2) contains a directory traversal vulnerability that allows unauthenticated attackers to read arbitrary server files by leveraging a predictable security nonce.
date: "2026-10-28T08:26:55Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:lumise:product_designer_for_woocommerce:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - directory-traversal
  - cve-2026-15323
vendors:
  - Lumise
products:
  - Product Designer for WooCommerce WordPress (<= 2.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server
    confidence_band: high
cves:
  - id: CVE-2026-15323
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15323
rules:
  - title: Detects CVE-2026-15323 Exploitation - Arbitrary File Read in Lumise
    description: Detects exploitation attempts against CVE-2026-15323 by identifying directory traversal characters in requests to the /?lumise=cart endpoint
    platform: sigma
    severity: high
    tactics:
      - discovery
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
    - action: Inventory all WordPress sites running Product Designer for WooCommerce plugin
      owner: IT Operations
      due: 24h
      evidence: Plugin version vulnerability
  hunt_leads:
    - lead: Search web logs for suspicious usage of /?lumise=ajax action=init followed by activity to /?lumise=cart
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The lumise_security nonce required to reach the vulnerable /?lumise=cart endpoint is freely obtainable... via the /?lumise=ajax action=init handler
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2.1.3 or later
      owner: IT Operations
      addresses: CVE-2026-15323
      evidence: Vulnerability present in versions up to, and including, 2.1.2
---

The Product Designer for WooCommerce WordPress plugin is vulnerable to directory traversal through the process_checkout function in versions 2.1.2 and earlier. An attacker can obtain a lumise_security nonce by calling the /?lumise=ajax action=init endpoint, which is accessible to unauthenticated users. This nonce can then be used to target the /?lumise=cart endpoint to read arbitrary files from the server filesystem. This flaw allows for the unauthorized disclosure of sensitive configuration data.

## Attack Chain

1. Attacker navigates to the public /?lumise=ajax action=init endpoint.
2. Attacker retrieves the lumise_security nonce from the application response.
3. Attacker crafts a request to the /?lumise=cart endpoint.
4. Attacker includes the harvested nonce and directory traversal sequences (e.g., ../) in the parameters.
5. The process_checkout function fails to sanitize path inputs, allowing access to files outside the intended directory.
6. The server returns the contents of the requested file in the HTTP response.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files from the WordPress server, potentially leading to the exposure of credentials, database configuration files (wp-config.php), or other sensitive system information.

## Recommendation

1. Upgrade the Product Designer for WooCommerce (Lumise) plugin to version 2.1.3 or later as soon as it becomes available.
2. Until a patch is applied, consider disabling the plugin or restricting access to the /?lumise= endpoints via a Web Application Firewall (WAF).
3. Monitor web server access logs for anomalous requests to /?lumise=cart containing path traversal characters like "../".
