---
title: Stored XSS Vulnerability in No External Links WordPress Plugin
slug: 2026-10-no-external-links-xss
description: The No External Links WordPress plugin (<= 5.2.0) is vulnerable to Stored Cross-Site Scripting (XSS) via the /goto/ redirect feature, allowing unauthenticated attackers to inject malicious scripts.
date: "2026-10-02T08:23:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:no_external_links_project:no_external_links:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-application
  - vulnerability
vendors:
  - WordPress
products:
  - No External Links (<= 5.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-95670
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95670
rules:
  - title: Detects CVE-2026-95670 Exploitation - XSS via /goto/ endpoint
    description: Detects HTTP requests to the /goto/ redirect endpoint containing suspicious Base64 encoded JavaScript payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade No External Links plugin to version > 5.2.0
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability exists in all versions up to 5.2.0
  enrichment_needed:
    - item: Exploit POC availability
      owner: CTI
      reason: Assess risk to internal environment
      evidence: NVD advisory
  mitigation_plan:
    - priority: immediate
      action: 'Disable ''Link Encoding: Base64'' in plugin settings'
      owner: IT Operations
      addresses: CVE-2026-95670
      evidence: Source notes exploitability depends on this setting
---

The 'No External Links' plugin for WordPress, in all versions up to and including 5.2.0, contains a Stored Cross-Site Scripting (XSS) vulnerability. The flaw originates from insufficient input sanitization and output escaping within the plugin's URL logging functionality. Specifically, the vulnerability resides in the /goto/ redirect mechanism when the 'Link Encoding: Base64' setting is enabled by an administrator. An unauthenticated attacker can craft a malicious URL containing a Base64-encoded JavaScript payload and trigger the storage of this script within the site's logs. When a user - such as an administrator - subsequently views the affected page or logs, the injected script executes in the context of the victim's browser. This could lead to session hijacking, unauthorized actions on behalf of the user, or further site compromise. 

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's session. Depending on the privileges of the victim viewing the logs, this could result in account takeover, defacement, or the injection of additional malicious content into the WordPress site. Given the plugin's function to manage external links, this vulnerability poses a significant risk to site integrity and user data privacy.

## Recommendation

- Upgrade the 'No External Links' plugin to the latest version (patch version > 5.2.0) immediately.
- Disable the 'Link Encoding: Base64' feature within the plugin settings until a patch is applied if immediate upgrading is not feasible.
- Monitor webserver access logs for anomalous requests to the '/goto/' directory containing Base64 strings.
- Implement a strong Content Security Policy (CSP) to mitigate the impact of potential XSS attacks by restricting the execution of inline scripts.
