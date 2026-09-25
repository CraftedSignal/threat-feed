---
title: Cross-Site Scripting Vulnerability in MediaWiki CirrusSearch Extension
slug: 2026-09-mediawiki-xss
description: A vulnerability in the CirrusSearch extension for MediaWiki allows remote, unauthenticated attackers to execute cross-site scripting (XSS) attacks through improper input sanitization.
date: "2026-09-25T14:01:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - web-vulnerability
  - mediawiki
vendors:
  - MediaWiki
products:
  - CirrusSearch
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The vulnerability exists in the CirrusSearch extension of MediaWiki, enabling XSS attacks.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3566
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update CirrusSearch extension to the latest version.
      owner: IT Operations
      due: 72h
      evidence: General security recommendation for software vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Review and harden Content Security Policy (CSP) to mitigate XSS risks.
      owner: IT Operations
      addresses: XSS vulnerability in CirrusSearch
      evidence: Standard defensive measure against XSS.
---

The CirrusSearch extension for MediaWiki, which provides search functionality via Elasticsearch, contains a cross-site scripting (XSS) vulnerability. An unauthenticated remote attacker can exploit this flaw by supplying specially crafted input to the search functionality that is not properly sanitized before being reflected in the user's browser. If successful, this attack allows for the execution of arbitrary JavaScript within the context of a victim's session, potentially leading to session hijacking, credential theft, or unauthorized actions performed on behalf of the user. This vulnerability highlights the importance of rigorous input validation in extensions that handle user-supplied query parameters and render output dynamically in the application interface. Defenders should monitor for unexpected script injection patterns in web server logs or via browser-based security telemetry.

## Impact

Successful exploitation of this vulnerability allows for the execution of malicious scripts in the browser of an authenticated or unauthenticated MediaWiki user. This can lead to account takeover, unauthorized modification of wiki content, or redirection to malicious sites, impacting the integrity and confidentiality of the affected MediaWiki instance.

## Recommendation

Update the CirrusSearch extension to the latest available version provided by the MediaWiki project to remediate the underlying sanitization flaw. Implement or update Content Security Policy (CSP) headers to restrict the execution of inline scripts and prevent unauthorized script injection.
