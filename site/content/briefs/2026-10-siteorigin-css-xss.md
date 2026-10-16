---
title: Stored DOM-Based Cross-Site Scripting in SiteOrigin CSS
slug: 2026-10-siteorigin-css-xss
description: The SiteOrigin CSS WordPress plugin contains a stored DOM-based XSS vulnerability via the 'url' parameter, allowing unauthenticated attackers to execute arbitrary web scripts.
date: "2026-10-16T06:26:38Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:siteorigin:css:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-application
  - wordpress
vendors:
  - SiteOrigin
products:
  - SiteOrigin CSS (<= 1.6.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-107764
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107764
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade SiteOrigin CSS plugin to version 1.6.8 or later
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability exists in versions up to and including 1.6.7
  mitigation_plan:
    - priority: immediate
      action: Upgrade SiteOrigin CSS plugin
      owner: IT Operations
      addresses: CVE-2026-107764
      evidence: NVD vulnerability details
---

The SiteOrigin CSS plugin for WordPress (versions 1.6.7 and prior) contains a stored DOM-based Cross-Site Scripting (XSS) vulnerability. The flaw exists due to insufficient sanitization of the comment_author_url parameter. Attackers can leverage the WordPress esc_url() function's behavior of preserving HTML entity-encoded characters to bypass intended input protections. By injecting crafted entity-encoded payloads into the 'Website' field of a comment, an unauthenticated attacker can ensure the malicious script is stored in the database. When the page is subsequently rendered, the browser performs a DOM-decode operation, executing the injected markup. This poses a significant risk as it allows for unauthorized script execution in the context of any user session that visits the compromised page, potentially leading to session hijacking or unauthorized administrative actions.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the victim's browser. This can lead to account takeover, session theft, or the execution of malicious actions within the WordPress dashboard if an administrator views the crafted comment. The vulnerability affects all users running SiteOrigin CSS version 1.6.7 or earlier on their WordPress installations.

## Recommendation

Update the SiteOrigin CSS plugin to the latest version (post-1.6.7) to resolve the input sanitization flaw. Monitor web server logs for HTTP POST requests directed toward comment submission endpoints that contain unusually long or character-encoded 'url' or 'comment_author_url' parameters.
