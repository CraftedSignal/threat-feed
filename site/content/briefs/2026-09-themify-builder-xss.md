---
title: Stored XSS in Themify Builder via css[fonts] Parameter
slug: 2026-09-themify-builder-xss
description: Themify Builder versions 7.8.1 and earlier are vulnerable to Stored Cross-Site Scripting (XSS) via the css[fonts] parameter, allowing unauthenticated attackers to inject malicious scripts due to exposed nonces.
date: "2026-09-25T08:58:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:themify:builder:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - xss
  - wordpress
  - cve-2026-95864
vendors:
  - Themify
products:
  - Themify Builder (<= 7.8.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages
    confidence_band: high
cves:
  - id: CVE-2026-95864
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95864
rules:
  - title: Detect CVE-2026-95864 Exploitation Attempt - Stored XSS via css[fonts]
    description: Detects potential exploitation attempts of CVE-2026-95864 by monitoring for suspicious script injection patterns within the css[fonts] parameter in HTTP POST requests.
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
    - Detection Engineering
  immediate_actions:
    - action: Review WordPress plugin inventory for Themify Builder installations.
      owner: IT Operations
      due: 48h
      evidence: Plugin version must be identified to assess risk.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Themify Builder to the latest version once a patch is confirmed available.
      owner: IT Operations
      addresses: CVE-2026-95864
      evidence: NVD vulnerability entry
---

Themify Builder, a popular WordPress plugin, contains a Stored Cross-Site Scripting (XSS) vulnerability in versions 7.8.1 and earlier, tracked as CVE-2026-95864. The flaw exists within the 'css[fonts]' parameter, which fails to adequately sanitize user-supplied input or escape output. 

The security impact is compounded by the fact that the required nonce is embedded within the site's front-end markup, accessible to any visitor. This effectively bypasses standard authentication requirements, allowing unauthenticated remote attackers to inject arbitrary web scripts into pages. When an authorized user or administrator accesses a compromised page, the injected script executes within the context of their session. This can lead to session hijacking, unauthorized administrative actions, or the redirection of users to malicious infrastructure. Defenders should prioritize updating the plugin to a patched version once available and monitor web server access logs for anomalous POST requests directed at plugin-related endpoints.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browser of any user viewing the injected content. This could result in unauthorized administrative actions, sensitive information disclosure via session theft, or the compromise of user accounts. The vulnerability affects all WordPress instances running Themify Builder 7.8.1 and earlier.

## Recommendation

- Monitor web server logs for suspicious POST requests containing unusual patterns in the 'css[fonts]' parameter.
- Implement a Content Security Policy (CSP) to mitigate the impact of XSS by restricting the sources from which scripts can be executed.
- Upgrade Themify Builder to the latest version immediately upon the release of a security patch by the vendor.
