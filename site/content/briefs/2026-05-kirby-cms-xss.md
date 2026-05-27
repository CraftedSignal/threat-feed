---
title: Kirby CMS Stored XSS Vulnerability in KirbyTags and Image Blocks (CVE-2026-45368)
slug: 2026-05-kirby-cms-xss
description: Kirby CMS is vulnerable to stored cross-site scripting (XSS) due to insufficient sanitization of links within KirbyTags and image blocks, allowing authenticated users with content editing privileges to inject malicious JavaScript that executes when other users interact with the crafted links on the site frontend; patched in versions 4.9.1 and 5.4.1.
date: "2026-05-27T17:44:19Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - xss
  - kirbycms
  - cve-2026-45368
vendors:
  - getkirby
products:
  - cms (<= 4.9.0)
  - cms (>= 5.0.0, <= 5.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-qvjf-922g-pj44
  - https://github.com/getkirby/kirby/releases/tag/4.9.1
  - https://github.com/getkirby/kirby/releases/tag/5.4.1
rules:
  - title: Detect Suspicious Javascript URI Scheme in Link Tag
    description: 'Detects CVE-2026-45368 exploitation —  attempts to inject malicious links with javascript:, vbscript:, livescript:, mocha:, jar:, or data: URI schemes in webserver logs.'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Kirby CMS Block HTML Importer XSS
    description: Detects CVE-2026-45368 exploitation — attempts to use the HTML importer for blocks to inject Javascript.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A stored cross-site scripting (XSS) vulnerability exists in Kirby CMS affecting sites that utilize the `(link: …)` KirbyTag, the `link:` parameter of the `(image: …)` KirbyTag, the built-in `image` block with a link, or the HTML importer for blocks. The vulnerability, identified as CVE-2026-45368, can be exploited by an authenticated Panel user with update permissions to `textarea` or `blocks` fields, or write access to content files via other means. Successful exploitation allows an attacker to inject malicious JavaScript into content, which will then execute in the browsers of other site visitors or logged-in users who interact with the crafted links. This can lead to session hijacking, data theft, or other malicious activities within the context of the affected user's browser session. The issue is patched in Kirby versions 4.9.1 and 5.4.1.

## Attack Chain

1. An attacker gains authenticated access to the Kirby CMS Panel with permissions to edit content.
2. The attacker navigates to a page or content section with a `textarea` or `blocks` field.
3. The attacker crafts a malicious link using either the `(link: …)` KirbyTag, the `link:` parameter of the `(image: …)` KirbyTag, the built-in `image` block, or the HTML importer. This link uses a `javascript:`, `vbscript:`, `livescript:`, `mocha:`, `jar:`, or `data:` URI scheme with an embedded JavaScript payload.
4. The attacker saves the content, persisting the malicious link in the CMS database.
5. A user visits the page containing the malicious link on the site frontend.
6. The malicious link is rendered as an `<a>` tag in the HTML of the page.
7. The user clicks on the malicious link.
8. The browser executes the JavaScript payload embedded in the `href` attribute of the link within the user's session, potentially allowing the attacker to perform actions on behalf of the user.

## Impact

Successful exploitation of this XSS vulnerability (CVE-2026-45368) could allow an attacker to execute arbitrary JavaScript code in the context of other users' browsers. This can lead to session hijacking, where the attacker gains control of a user's authenticated session within the Kirby CMS Panel, potentially escalating privileges to administrative roles. Other potential impacts include defacement of the website, theft of sensitive information, or redirection of users to malicious websites. The severity is high due to the ease of exploitation and potential for widespread impact on site visitors and administrators.

## Recommendation

*   Upgrade Kirby CMS to version 4.9.1 or 5.4.1 or later to patch CVE-2026-45368, as indicated in the patch information.
*   Deploy the Sigma rule `Detect Suspicious Javascript URI Scheme in Link Tag` to detect attempts to inject malicious links with dangerous URI schemes.
*   Educate content editors about the risks of XSS and the importance of sanitizing user-supplied input, referencing the affected components described in this brief.
