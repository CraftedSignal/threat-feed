---
title: Stored XSS in JetFormBuilder WordPress Plugin (CVE-2026-97342)
slug: 2026-10-02-jetformbuilder-xss
description: An unauthenticated stored XSS vulnerability in the JetFormBuilder WordPress plugin allows attackers to inject arbitrary web scripts via the 'choice' Post Meta field.
date: "2026-10-02T08:24:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jetformbuilder:dynamic_blocks_form_builder:*:*:*:*:*:*:*:*
tags:
  - web-application
  - wordpress
  - xss
vendors:
  - JetFormBuilder
products:
  - JetFormBuilder — Dynamic Blocks Form Builder (<= 3.6.5.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The injected payload is submitted via the unauthenticated wp_ajax_nopriv_jet_form_builder_submit endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-97342
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97342
rules:
  - title: Detects CVE-2026-97342 Exploitation - XSS Injection via Form Submission
    description: Detects unauthenticated POST requests to the JetFormBuilder submission endpoint containing common XSS payloads in parameters.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade JetFormBuilder plugin to latest version
      owner: IT Operations
      due: 48h
      evidence: Plugin version <= 3.6.5.4 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Implement WAF blocking for script-like strings on the admin-ajax endpoint
      owner: SOC
      addresses: CVE-2026-97342
      evidence: Source identifies vector via wp_ajax_nopriv_jet_form_builder_submit
---

The JetFormBuilder - Dynamic Blocks Form Builder plugin for WordPress is affected by a stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-97342. The flaw exists in all versions up to and including 3.6.5.4. It stems from insufficient input sanitization and output escaping when handling the 'choice' Post Meta field during the Insert/Update Post action. 

Unauthenticated attackers can exploit this by sending a crafted request to the `wp_ajax_nopriv_jet_form_builder_submit` endpoint. The malicious payload is stored verbatim in the WordPress post meta database. When a user interacts with a page containing the 'Select Field' block, the plugin renders the stored raw meta values as option attributes and label content, leading to the execution of the injected script in the context of the user's browser. This vulnerability poses a significant risk for session hijacking and unauthorized administrative actions if an administrator views the compromised page.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browser of any user viewing a page where the malicious form meta is rendered. This can lead to session token theft, the execution of unauthorized actions within the WordPress dashboard, or credential harvesting, impacting all organizations utilizing versions 3.6.5.4 or earlier of the JetFormBuilder plugin.

## Recommendation

1. Patch immediately by updating the JetFormBuilder - Dynamic Blocks Form Builder plugin to a version greater than 3.6.5.4.
2. Audit WordPress site logs for anomalous requests to the `wp_ajax_nopriv_jet_form_builder_submit` endpoint that include script tags or unusual characters.
3. Deploy web application firewall (WAF) rules to detect and block incoming HTTP requests targeting the `jet_form_builder_submit` action that contain XSS vectors (e.g., `<script>`, `onerror`, `onload`).
