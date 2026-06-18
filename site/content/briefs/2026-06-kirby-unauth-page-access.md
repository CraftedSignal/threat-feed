---
title: Kirby CMS Missing Authorization Vulnerability in /api/site/find (CVE-2026-54005)
slug: 2026-06-kirby-unauth-page-access
description: An authenticated user can exploit CVE-2026-54005, a high-severity missing authorization vulnerability in Kirby CMS versions <= 4.9.3 and from 5.0.0-alpha.1 to <= 5.4.3, via the `/api/site/find` REST API route to bypass `pages.access` permissions and retrieve sensitive content and metadata from unauthorized pages.
date: "2026-06-18T15:24:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cms
  - vulnerability
  - kirby
  - information-disclosure
  - api
  - webserver
vendors:
  - Kirby
products:
  - 'composer/getkirby/cms (vulnerable: <= 4.9.3)'
  - 'composer/getkirby/cms (vulnerable: >= 5.0.0-alpha.1, <= 5.4.3)'
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Systems
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/advisories/GHSA-r3w8-2c5r-h9j9
rules:
  - title: Detect CVE-2026-54005 Exploitation — Access to Kirby /api/site/find
    description: Detects HTTP GET requests to the vulnerable `/api/site/find` endpoint in Kirby CMS (CVE-2026-54005), which indicates an attempt to exploit the missing authorization check for sensitive page content disclosure.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1213
      - T1562
    data_sources:
      - webserver
  - title: Detect CVE-2026-54005 Exploitation — Multiple Page ID/UUID Requests
    description: Detects HTTP GET requests to the Kirby `/api/site/find` endpoint that include multiple page IDs or UUIDs in the query parameters, potentially indicating an attacker's attempt to enumerate or retrieve unauthorized content in bulk via CVE-2026-54005.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1213
      - T1562
    data_sources:
      - webserver
rules_count: 2
---

A high-severity missing authorization vulnerability, identified as CVE-2026-54005, affects Kirby CMS in versions up to 4.9.3 and from 5.0.0-alpha.1 up to 5.4.3. This flaw allows authenticated users to bypass `pages.access` permissions and retrieve full content and metadata for arbitrary pages they are not authorized to view. The vulnerability resides in the `/api/site/find` REST API route, which fails to properly check user permissions for queried pages. Discovered by Rizky Muhammad (@EvidentObscurity), this issue could lead to significant sensitive information disclosure, particularly in sites where user roles are configured with granular page access restrictions. The vulnerability does not affect write actions or draft pages, but the ability to enumerate and extract unauthorized published content poses a substantial risk to data confidentiality.

## Attack Chain

1.  An attacker obtains valid credentials for a Kirby CMS user account, potentially through phishing, brute-force, or exploitation of other vulnerabilities.
2.  The authenticated attacker logs into the Kirby CMS administration panel or directly interacts with the Kirby API.
3.  The attacker crafts an HTTP GET request targeting the vulnerable `/api/site/find` REST API route.
4.  The request includes `page IDs` or `UUIDs` of specific pages the attacker wishes to access, even if their assigned role does not grant `pages.access` permission to those pages.
5.  Due to the missing authorization check (CVE-2026-54005), the Kirby application processes the request without validating the user's `pages.access` rights for the specified pages.
6.  The server responds with the full content and metadata of the requested published pages, including potentially sensitive information, bypassing the intended access controls.
7.  The attacker extracts and analyzes the disclosed data, potentially leading to further compromise or sensitive data exfiltration.

## Impact

Successful exploitation of CVE-2026-54005 leads to the unauthorized disclosure of sensitive information. Attackers can retrieve the full content and metadata of any published page within the affected Kirby CMS, even if their account lacks explicit `pages.access` permissions for those pages. This includes confirming the existence of pages and extracting confidential data stored in page fields. While the vulnerability does not allow for write access or exposure of draft pages, the compromise of information confidentiality can be significant for organizations that rely on Kirby CMS for content management with differentiated access levels. The specific number of victims and sectors affected are not publicly detailed, but any Kirby site with the specified version range and restricted `pages.access` configurations is at risk.

## Recommendation

*   Immediately patch Kirby CMS to version [4.9.4](https://github.com/getkirby/kirby/releases/tag/4.9.4), [5.4.4](https://github.com/getkirby/kirby/releases/tag/5.4.4), or a later version to remediate CVE-2026-54005.
*   Deploy the provided Sigma rules to your SIEM solution to detect suspicious activity related to the `/api/site/find` endpoint.
*   Monitor web server access logs for anomalous or high-volume requests targeting the `/api/site/find` route from specific users or IP addresses.
