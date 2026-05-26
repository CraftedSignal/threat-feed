---
title: Kirby CMS Vulnerable to Cross-Site Scripting (XSS) via List Field Content (CVE-2026-44175)
slug: 2026-05-kirby-cms-xss
description: Kirby CMS is vulnerable to cross-site scripting (XSS) via the list field or list block, allowing an authenticated Panel user with update permission to inject malicious HTML code into the content file, which is then executed in the browsers of site visitors and logged-in users; the vulnerability is tracked as CVE-2026-44175 and has been patched in versions 4.9.1 and 5.4.1.
date: "2026-05-26T23:52:25Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - xss
  - CVE-2026-44175
  - kirby-cms
  - web-application
vendors:
  - Kirby
products:
  - cms (<= 4.9.0)
  - cms (>= 5.0.0, <= 5.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-5fhx-9q32-q257
  - https://getkirby.com/docs/reference/panel/fields/list
  - https://getkirby.com/docs/guide/templates/escaping
rules:
  - title: Detects CVE-2026-44175 Exploitation — Kirby CMS List Field XSS Attempt
    description: Detects CVE-2026-44175 exploitation — Attempts to inject HTML or JavaScript code into the Kirby CMS list field via a POST request to the API.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-44175 Exploitation — Kirby CMS List Field XSS Response
    description: Detects CVE-2026-44175 exploitation — HTTP responses containing potentially malicious HTML code originating from the Kirby CMS list field on the site frontend.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Kirby CMS versions prior to 4.9.1 and from 5.0.0 to 5.4.0 are susceptible to a stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-44175, stemming from the improper sanitization of list field content. This vulnerability affects all Kirby sites that use the list field or list block when content is authored by users who may not be fully trusted. An attacker requires an authenticated Panel user with update permission to any list field or list block. The attack surfaces in the site frontend, not the Panel itself. Kirby sites are not affected if they don't use the list field (or blocks field with the list block) in any of their blueprints, or if every user who can edit content is fully trusted.

## Attack Chain

1. An attacker gains authenticated access to the Kirby Panel with update permissions.
2. The attacker identifies a page or content structure that utilizes a 'list' field or 'blocks' field with the 'list' block.
3. The attacker crafts a malicious payload containing JavaScript code embedded within HTML tags.
4. The attacker injects the malicious payload into the 'list' field content, either directly via API or through the Panel's editing interface.
5. The attacker saves the modified content. The injected payload is stored within the content files on the server.
6. A user (either another authenticated user or an unauthenticated visitor) requests the page containing the affected 'list' field on the site frontend.
7. The server renders the page, including the injected malicious HTML code from the 'list' field.
8. The user's browser executes the injected JavaScript code, potentially leading to session hijacking, data theft, or other malicious actions.

## Impact

Successful exploitation of this XSS vulnerability (CVE-2026-44175) allows an attacker to execute arbitrary JavaScript code in the context of a user's browser session. This can lead to credential theft, session hijacking, defacement of the website, or redirection to malicious sites. The impact is high severity, as it affects all Kirby sites using the list field when content is authored by users who may not be fully trusted. The number of victims depends on the number of affected sites and the frequency with which users access pages containing the injected payload.

## Recommendation

*   Upgrade to Kirby CMS version 4.9.1 or 5.4.1 or later to apply the patch that sanitizes list field content, mitigating the XSS vulnerability (CVE-2026-44175).
*   Implement strict input validation and output encoding mechanisms on all user-supplied data within the Kirby CMS environment.
*   Review existing content for potentially malicious code within list fields and sanitize the content.
*   Deploy a Web Application Firewall (WAF) with rules to detect and block XSS attacks targeting Kirby CMS, specifically focusing on the 'list' field and 'blocks' field inputs.
*   Enable logging for all API requests to the Kirby Panel to monitor for suspicious activity and potential payload injections.
