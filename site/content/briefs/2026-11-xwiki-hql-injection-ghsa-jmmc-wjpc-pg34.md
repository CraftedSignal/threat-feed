---
brief_id: brief-2026-11-20-xwiki-hql-injection-ghsa-jmmc-wjpc-pg34
event_id: brief-2026-11-20-xwiki-hql-injection-ghsa-jmmc-wjpc-pg34
revision: 1
activity_at: "2026-11-20T02:07:34Z"
title: 'XWiki Platform: REST API HQL injection (CVE-2026-61689)'
slug: 2026-11-xwiki-hql-injection-ghsa-jmmc-wjpc-pg34
description: An unauthenticated HQL injection vulnerability in the XWiki Platform REST API allows attackers to perform blind data extraction from the underlying database, including sensitive password hashes.
date: "2026-11-20T02:07:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:xwiki:xwiki_platform_rest_server:*:*:*:*:*:*:*:*
vendors:
  - XWiki
products:
  - xwiki-platform-rest-server
product_versions:
  - product: xwiki-platform-rest-server
    range: '>= 17.0.0-rc-1, < 17.10.5'
  - product: xwiki-platform-rest-server
    range: '>= 18.0.0-rc-1, < 18.2.0'
  - product: xwiki-platform-rest-server
    range: '>= 4.3-milestone-1, < 16.10.18'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The /rest/wikis/{wikiName}/query REST endpoint permits HQL query construction that can combine blind conditions with FROM-clause injection to join BaseObject and StringProperty, bypassing the SELECT-column whitelist.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An unauthenticated attacker can recover database values from inaccessible pages, including salted SHA1 password hashes and passwords stored in configuration properties.
    confidence_band: high
cves:
  - id: CVE-2026-61689
    epss: 0.00531
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-jmmc-wjpc-pg34
  - https://cveawg.mitre.org/api/cve/CVE-2026-61689
action_plan:
  priority: elevated
  hunt_leads:
    - lead: Search for high volumes of requests to the XWiki REST query endpoint from single source IP addresses, indicating potential blind extraction attempts.
      technique_id: T1190
      data_needed:
        - webserver request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: For a typical password hash, this requires about 800 requests to the REST API.
  mitigation_plan:
    - priority: immediate
      action: Upgrade xwiki-platform-rest-server to 16.10.18, 17.10.5, or 18.2.0 or later.
      evidence: The vulnerability has been fixed in XWiki 16.10.18, 17.10.5 and 18.2.0 by disabling the HQL and WXQL queries in the REST API by default.
    - priority: short_term
      action: Block access to /rest/wikis/*/query at the WAF or reverse proxy.
      evidence: The requests to the /rest/wikis/{wikiName}/query endpoint could be blocked at the web server/reverse proxy level.
---

## Overview
XWiki Platform is susceptible to an HQL injection vulnerability (CVE-2026-61689) in the `/rest/wikis/{wikiName}/query` REST endpoint. The vulnerability enables attackers to bypass the HQL validator's SELECT-column whitelist by using FROM-clause injection to join `BaseObject` and `StringProperty` tables. Attackers can leverage blind techniques to exfiltrate database content, such as salted SHA1 password hashes and stored configuration secrets, without authentication. Furthermore, the construction of resource-intensive queries can lead to system performance degradation and potential denial-of-service conditions.

## Impact
Successful exploitation allows unauthenticated attackers to recover sensitive information stored in the XWiki database. For a typical password hash, extraction requires approximately 800 API requests. Salted SHA1 hashes may be subject to offline cracking. High-load queries can also negatively affect platform availability.

## Recommendation
- Update to XWiki 16.10.18, 17.10.5, or 18.2.0, which disable HQL and XWQL queries in the REST API by default.
- If patching is not immediately feasible, block access to the `/rest/wikis/{wikiName}/query` endpoint at the web server or reverse proxy layer.
