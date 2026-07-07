---
title: MediaWiki Maps Stored XSS via display_map `overlays` Parameter (CVE-2026-52854)
slug: 2026-07-mediawiki-maps-xss
description: A high-severity stored cross-site scripting (XSS) vulnerability, CVE-2026-52854, exists in the MediaWiki Maps extension (versions prior to 12.1.3), allowing any authenticated user with edit permissions to inject malicious JavaScript into the `overlays` parameter of the `display_map` parser function, leading to arbitrary client-side code execution in a victim's browser.
date: "2026-07-03T11:51:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - mediawiki
  - web-vulnerability
  - web-application
vendors:
  - MediaWiki
products:
  - mediawiki/maps (< 12.1.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: Stored XSS can be performed by inserting malicious HTML... executing the injected JavaScript code in the victim's browser.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: ""
    evidence: Stored XSS can be performed by any user with the `edit` permission.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4h7g-5542-v3fc
rules:
  - title: Detect CVE-2026-52854 Exploitation Attempt — MediaWiki Maps XSS Injection
    description: Detects CVE-2026-52854 exploitation attempts by identifying wikitext containing the 'display_map' function with 'service=leaflet' and XSS payloads within the 'overlays' parameter in web server request queries.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
---

This brief details CVE-2026-52854, a high-severity stored cross-site scripting (XSS) vulnerability discovered in the MediaWiki Maps extension, specifically affecting versions prior to 12.1.3. The vulnerability stems from improper handling of the `overlays` parameter within the `display_map` parser function when utilizing the 'leaflet' service. The Maps extension fails to adequately escape user-supplied overlay names before they are passed to the Leaflet JavaScript library, which then renders these unescaped inputs as HTML. This flaw allows any authenticated user with `edit` permissions to inject and store arbitrary client-side JavaScript code into wikitext. This code will then execute in the browser of any user viewing the affected page, potentially leading to session hijacking, credential theft, or further client-side attacks against visitors of the MediaWiki instance. The issue was published on 2026-07-02.

## Attack Chain

1.  An attacker gains authenticated access to a MediaWiki instance with `edit` permissions.
2.  The attacker navigates to an existing wiki page or creates a new one to edit its content.
3.  The attacker crafts and inserts malicious wikitext into the page content, specifically utilizing the `display_map` parser function.
4.  Within the `display_map` function, the attacker sets the `service` parameter to `leaflet`.
5.  The attacker injects a JavaScript payload (e.g., `<img src=x onerror="alert(1);">`) into the `overlays` parameter, like `overlays=OpenTopoMap.<img src=x onerror="alert(1);">`.
6.  The attacker saves or previews the modified wiki page, causing the MediaWiki application to process the wikitext.
7.  The Maps extension passes the unescaped `overlays` value directly to the Leaflet JavaScript library when rendering the map.
8.  When a victim views the affected wiki page, their browser renders the malicious HTML supplied by the Leaflet library, executing the injected JavaScript code in the victim's browser context.

## Impact

Successful exploitation of CVE-2026-52854 results in stored cross-site scripting, enabling an attacker with `edit` permissions to execute arbitrary JavaScript code in the context of a victim's browser. This can lead to various malicious outcomes, including session hijacking, defacement of web pages, redirection to phishing sites, or further client-side attacks designed to steal sensitive user data or credentials. While no specific victim count or targeted sectors are mentioned, any MediaWiki instance running the vulnerable Maps extension (versions prior to 12.1.3) is susceptible, potentially impacting all users who view pages containing the injected content.

## Recommendation

*   Patch CVE-2026-52854 immediately by updating the `composer/mediawiki/maps` extension to version 12.1.3 or higher.
*   Deploy the `Detect CVE-2026-52854 Exploitation Attempt — MediaWiki Maps XSS Injection` Sigma rule provided in this brief to your SIEM and tune for your environment.
*   Enable comprehensive web server logging to capture `cs-uri-query` and `cs-method` for all requests, especially those made to editing endpoints.
*   Implement a Web Application Firewall (WAF) to detect and block common XSS payloads in request parameters and body content.
