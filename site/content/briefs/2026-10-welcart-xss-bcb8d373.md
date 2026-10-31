---
brief_id: brief-2026-10-31-welcart-xss-bcb8d373
event_id: brief-2026-10-31-welcart-xss-bcb8d373
revision: 1
activity_at: "2026-10-31T07:52:32Z"
title: 'Welcart e-Commerce: Stored Cross-Site Scripting (CVE-2026-118070)'
slug: 2026-10-welcart-xss-bcb8d373
description: The Welcart e-Commerce plugin for WordPress contains a stored cross-site scripting (XSS) vulnerability via the 'gid' parameter, allowing unauthenticated attackers to execute arbitrary JavaScript in the administrative dashboard.
date: "2026-10-31T07:52:32Z"
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
  validation_status: Verified against NVD disclosure.
cpes:
  - cpe:2.3:a:welcart:welcart_e-commerce:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-application
  - wordpress
  - cve-2026-118070
vendors:
  - Welcart
products:
  - Welcart e-Commerce (<= 2.12.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The payload is staged by an unauthenticated visitor who forges the ROBOT PAYMENT browser-return request.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-118070
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118070
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory WordPress sites running Welcart e-Commerce and identify versions <= 2.12.5.
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in Welcart e-Commerce plugin versions <= 2.12.5.
  hunt_leads:
    - lead: Search WordPress access logs for anomalous POST requests to ROBOT PAYMENT return endpoints containing script tags or JavaScript event handlers in the 'gid' parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The payload is staged by an unauthenticated visitor who forges the ROBOT PAYMENT browser-return request.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Welcart e-Commerce to a patched version once released.
      owner: IT Operations
      addresses: CVE-2026-118070
      evidence: Plugin vulnerable in versions <= 2.12.5.
---

The Welcart e-Commerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'gid' parameter in all versions up to and including 2.12.5. Insufficient input sanitization and output escaping allow unauthenticated attackers to inject malicious web scripts into order metadata. The script executes within the context of an administrator's browser when they access the compromised order details in the WordPress admin panel.

## Attack Chain

1. Attacker identifies a target WordPress site running a vulnerable version of the Welcart e-Commerce plugin.
2. Attacker initiates a forged ROBOT PAYMENT browser-return request.
3. Attacker injects a malicious JavaScript payload into the 'gid' parameter of the request.
4. The Welcart plugin improperly sanitizes the 'gid' input and saves it into the order metadata within the WordPress database.
5. An administrator logs into the WordPress dashboard and navigates to the compromised order page.
6. The injected JavaScript payload executes in the administrator's browser session.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the administrative context. This can lead to unauthorized actions performed on behalf of the administrator, session hijacking, or exfiltration of sensitive administrative information.

## Recommendation

- Upgrade the Welcart e-Commerce plugin to a version beyond 2.12.5 once a fix is available from the vendor.
- Until patched, restrict access to the ROBOT PAYMENT browser-return endpoint to trusted sources or disable the integration if not required.
- Implement Content Security Policy (CSP) headers to mitigate the impact of XSS vulnerabilities by restricting the sources from which scripts can execute.
