---
title: Stored Cross-Site Scripting Vulnerability in WP Rocket
slug: 2026-08-wp-rocket-xss
description: WP Rocket versions up to and including 3.21.0.1 are vulnerable to unauthenticated Stored Cross-Site Scripting via the rocket_beacon AJAX endpoint.
date: "2026-08-28T17:13:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp-rocket:wp-rocket:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
  - vulnerability
vendors:
  - WP Rocket
products:
  - WP Rocket (<= 3.21.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-5934
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5934
rules:
  - title: Detect CVE-2026-5934 Exploitation - Stored XSS in WP Rocket
    description: Detects potential exploitation attempts by identifying requests to the rocket_beacon endpoint containing common XSS script tags.
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
    - action: Inventory all WordPress installations and identify versions of WP Rocket running
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerable versions up to 3.21.0.1
  mitigation_plan:
    - priority: immediate
      action: Upgrade WP Rocket to the patched version immediately
      owner: IT Operations
      addresses: CVE-2026-5934
      evidence: NVD vulnerability disclosure
---

The WP Rocket plugin for WordPress, in versions up to and including 3.21.0.1, contains a critical Stored Cross-Site Scripting (XSS) vulnerability identified as CVE-2026-5934. The flaw originates from insufficient input sanitization and output escaping mechanisms within the 'rocket_beacon' AJAX endpoint. This vulnerability allows unauthenticated attackers to inject arbitrary malicious web scripts into the plugin's data handling processes. When a user - typically an administrator - accesses the page where the injected script is stored, the browser executes the malicious code. This could lead to session hijacking, unauthorized administrative actions, or persistent defacement of the affected WordPress instance. Defenders should prioritize updating to the latest version to mitigate this injection vector.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's session. This poses a significant risk to WordPress site integrity, potentially allowing attackers to steal session cookies, perform unauthorized configuration changes, or redirect traffic. The vulnerability impacts all WordPress sites running vulnerable versions of the WP Rocket plugin.

## Recommendation

1. Upgrade the WP Rocket plugin to the version that includes the patch for CVE-2026-5934.
2. Implement a strict Content Security Policy (CSP) to mitigate the impact of unauthorized script execution.
3. Monitor web server logs for suspicious requests targeting the 'rocket_beacon' AJAX endpoint.
