---
brief_id: brief-2026-11-07-payever-rce
event_id: brief-2026-11-07-payever-rce
revision: 1
activity_at: "2026-11-07T03:46:01Z"
title: 'payever - WooCommerce Gateway: Unauthenticated remote code execution (CVE-2026-93754)'
slug: 2026-11-payever-rce
description: The payever WooCommerce Gateway plugin for WordPress contains an arbitrary file upload vulnerability in versions 4.8.0 and earlier that allows unauthenticated remote code execution.
date: "2026-11-07T03:46:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:payever:payever_woocommerce_gateway:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - arbitrary-file-upload
  - rce
  - web-application-vulnerability
vendors:
  - payever
products:
  - payever – WooCommerce Gateway (<= 4.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The payever – WooCommerce Gateway plugin for WordPress is vulnerable to arbitrary file upload leading to remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to write an executable PHP file and achieve remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-93754
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93754
rules:
  - title: Detects CVE-2026-93754 Exploitation - Unauthorized WooCommerce API Callbacks
    description: Detects unauthenticated HTTP requests to vulnerable payever WooCommerce Gateway API endpoints
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
    - SOC
  immediate_actions:
    - action: Patch payever - WooCommerce Gateway plugin to version > 4.8.0
      owner: IT Operations
      due: 24h
      evidence: Vulnerable in versions up to, and including, 4.8.0.
  hunt_leads:
    - lead: Identify newly created .php files in the /wp-content/uploads/ directory
      technique_id: T1505.003
      data_needed:
        - File system change logs or web server file audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: upload_image() routine writes a remotely fetched file to the public uploads directory
  mitigation_plan:
    - priority: immediate
      action: Disable the payever plugin if an update is not immediately available
      owner: IT Operations
      addresses: CVE-2026-93754
      evidence: Vulnerable due to lack of authentication in API callbacks
---

The payever - WooCommerce Gateway plugin for WordPress (versions 4.8.0 and below) is vulnerable to an arbitrary file upload flaw that leads to remote code execution (RCE). The plugin exposes three WooCommerce-API callbacks (`payever_set_sandbox_api_keys`, `payever_toggle_subscription`, `payever_synchronization_incoming`) that lack authentication, authorization, or nonce verification. 

The `upload_image()` routine within these callbacks fetches a file from a remote URL and writes it to the public WordPress uploads directory. Because the filename is derived from attacker-controlled input using `basename()` before the file type is validated, an attacker can force the plugin to write an executable PHP file to the server.

## Impact
An unauthenticated remote attacker can upload arbitrary PHP scripts to the web server, leading to full remote code execution.

## Recommendation
- Update the "payever - WooCommerce Gateway" plugin to the latest available version beyond 4.8.0.
- Implement access controls or WAF rules to restrict access to the WooCommerce API callbacks mentioned.
- Audit the `/wp-content/uploads/` directory for suspicious PHP files or scripts that were uploaded recently.
