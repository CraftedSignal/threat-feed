---
title: XWiki Unauthenticated XAR Import via REST API
slug: 2026-05-xwiki-xar-import
description: An unauthenticated attacker can create or update documents in the target XWiki instance by exploiting the XAR import functionality through the `/wikis/{wikiName}` REST endpoint due to missing authentication and authorization checks, as detailed in CVE-2026-33137.
date: "2026-05-26T18:59:47Z"
lastmod: "2026-08-27T00:35:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-PORTBUSTER1337-CVE-2026-33137&utm_source=rss&utm_medium=rss
tags:
  - xwiki
  - xar
  - unauthenticated
  - rce
  - cve-2026-33137
vendors:
  - XWiki
products:
  - xwiki-platform-rest-server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-33137
    epss: 0.00594
references:
  - https://github.com/advisories/GHSA-qrvh-r3f2-9h4r
  - https://jira.xwiki.org/browse/XWIKI-23953
  - https://github.com/xwiki/xwiki-platform/commit/4b7b95b79256374d487e9ece1dc48f527966990f
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-PORTBUSTER1337-CVE-2026-33137&utm_source=rss&utm_medium=rss
rules:
  - title: Detect XWiki Unauthenticated XAR Import via REST API
    description: Detects CVE-2026-33137 exploitation — Unauthenticated XAR import via the /wikis/{wikiName} REST endpoint in XWiki.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect XWiki Unauthenticated XAR Import via REST API - Content Check
    description: Detects CVE-2026-33137 exploitation — Unauthenticated XAR import via the /wikis/{wikiName} REST endpoint in XWiki by checking content type
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-08-27T00:35:46Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-PORTBUSTER1337-CVE-2026-33137&utm_source=rss&utm_medium=rss
---

XWiki is susceptible to an unauthenticated XAR import vulnerability, identified as CVE-2026-33137, affecting versions 15.10.6 before 16.10.17, 17.0.0-rc-1 before 17.4.9, 17.5.0 before 17.10.3, and 18.0.0-rc-1 before 18.1.0-rc-1. The vulnerability resides in the `/wikis/{wikiName}` REST endpoint, which allows for the execution of XAR imports without proper authentication or authorization checks. This flaw allows an attacker to create or modify documents within the target wiki instance, potentially leading to arbitrary code execution or data manipulation. Defenders should prioritize patching vulnerable XWiki installations or implementing HTTP proxy rules to mitigate this risk.

## Attack Chain

1. An attacker identifies a vulnerable XWiki instance with an exposed `/wikis/{wikiName}` REST endpoint.
2. The attacker crafts a malicious XAR file containing payloads to create or modify documents.
3. The attacker sends an HTTP POST request to the `/wikis/{wikiName}` endpoint, including the malicious XAR file in the request body.
4. The XWiki instance processes the request without authentication or authorization.
5. The XAR file is imported, leading to the creation or modification of documents within the specified wiki.
6. The attacker gains unauthorized access to the modified documents.
7. The attacker leverages the modified documents to execute arbitrary code or manipulate data within the XWiki instance.

## Impact

Successful exploitation of CVE-2026-33137 allows unauthenticated attackers to create, modify, or delete content within the XWiki platform. This can lead to complete compromise of the XWiki instance, including unauthorized data access, data manipulation, and potentially arbitrary code execution on the server. The impact is significant, particularly for organizations relying on XWiki for critical knowledge management and collaboration.

## Recommendation

*   Upgrade XWiki installations to patched versions: 16.10.17, 17.4.9, 17.10.3, 18.0.1, or 18.1.0-rc-1 to address CVE-2026-33137.
*   Implement an HTTP proxy rule to block POST requests to the `/wikis/{wikiName}` endpoint as a temporary workaround.
*   Deploy the Sigma rule "Detect XWiki Unauthenticated XAR Import via REST API" to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious POST requests to the `/wikis/{wikiName}` endpoint.
