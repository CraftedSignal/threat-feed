---
brief_id: brief-2026-11-06-graphina-xss
event_id: brief-2026-11-06-graphina-xss
revision: 1
activity_at: "2026-11-06T11:05:21Z"
title: 'Graphina - Charts and Graphs For Elementor: Stored Cross-Site Scripting (CVE-2026-110291)'
slug: 2026-11-graphina-xss
description: The Graphina - Charts and Graphs For Elementor WordPress plugin is vulnerable to stored cross-site scripting due to insufficient input sanitization of chart settings, allowing unauthenticated attackers to execute arbitrary web scripts.
date: "2026-11-06T11:05:21Z"
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
cpes:
  - cpe:2.3:a:graphina:charts_and_graphs_for_elementor:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - plugin
  - xss
  - vulnerability
vendors:
  - Graphina
products:
  - Graphina – Charts and Graphs For Elementor (<= 3.1.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-110291
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110291
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all WordPress sites utilizing the Graphina - Charts and Graphs For Elementor plugin.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects plugin version 3.1.13 and earlier.
  hunt_leads:
    - lead: Identify HTTP POST requests to WordPress REST API endpoints containing suspicious event handlers in chart settings.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - WAF logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Payloads contain event-handler fragments that bypass kses_post_deep.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest patched version of the plugin as soon as available.
      owner: IT Operations
      addresses: CVE-2026-110291
      evidence: Plugin is vulnerable in versions <= 3.1.13.
---

The Graphina - Charts and Graphs For Elementor plugin for WordPress contains a stored cross-site scripting (XSS) vulnerability in versions 3.1.13 and earlier. The flaw resides in the handling of the 'iq_tree_chart_node_font_family' parameter and other text controls serialized into 'chart_data['settings']'. Insufficient input sanitization allows malicious payloads to persist in the database. Elementor's 'Utils::kses_post_deep()' function fails to sanitize these inputs because the payloads can be crafted to avoid disallowed HTML tags while including event handlers.

## Impact
Successful exploitation allows unauthenticated attackers to inject malicious scripts into WordPress pages. These scripts execute in the browser of any user who accesses the compromised page, potentially leading to unauthorized actions, session hijacking, or credential theft.

## Recommendation
- Update the Graphina - Charts and Graphs For Elementor plugin to the version containing the security fix (if available) or disable the plugin if no patch is available.
- Implement a Web Application Firewall (WAF) to block requests containing suspicious event-handler attributes (e.g., 'onmouseover', 'onerror') within POST parameters targeted at the WordPress REST API or administrative endpoints.
- Audit existing chart data records for injected JavaScript payloads in the 'settings' column.
