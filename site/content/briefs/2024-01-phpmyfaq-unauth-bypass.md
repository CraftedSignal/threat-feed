---
title: phpMyFAQ Unauthenticated FAQ Permission Bypass via Solution ID Enumeration
slug: 2024-01-phpmyfaq-unauth-bypass
description: phpMyFAQ version 4.1.1 and earlier is vulnerable to an unauthenticated FAQ permission bypass, allowing attackers to enumerate solution IDs and discover restricted FAQ titles due to missing permission filters in key functions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - phpMyFAQ
  - unauthenticated access
  - information disclosure
  - web server
vendors:
  - phpmyfaq
products:
  - phpmyfaq (<= 4.1.1)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://github.com/advisories/GHSA-99qv-g4x9-mgc3
rules:
  - title: phpMyFAQ Unauthenticated Solution ID Enumeration
    description: Detects unauthenticated enumeration of solution IDs in phpMyFAQ, indicating a potential information disclosure attempt.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: phpMyFAQ Solution ID Access Redirect
    description: Detects access to solution_id URLs which results in a redirect, potentially exposing restricted FAQ titles.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

phpMyFAQ version 4.1.1 and earlier contains a vulnerability that allows unauthenticated users to bypass intended access restrictions on FAQ entries. The vulnerability stems from the `/solution_id_{id}.html` route, which leverages the `getIdFromSolutionId()` function lacking proper permission checks. Additionally, the `getFaqBySolutionId()` function incorporates an explicit fallback mechanism that also bypasses permission filters. By sequentially querying solution IDs, an attacker can discover the existence and titles of FAQs intended for specific user groups or administrators. This affects deployments hosting sensitive internal knowledge alongside public content, impacting the confidentiality of restricted information. The vulnerability was reported on May 6, 2026.

## Attack Chain

1. An unauthenticated attacker sends a GET request to `/solution_id_{id}.html`, where `{id}` is a sequentially incremented integer.
2. The phpMyFAQ server receives the request and calls `Faq::getIdFromSolutionId()` to retrieve FAQ data.
3. `getIdFromSolutionId()` executes an SQL query that joins `faqdata` and `faqcategoryrelations` based on `solution_id` without applying any permission filters.
4. The server constructs a redirect URL using the retrieved data, including the FAQ's category ID, record ID, language, and a slugified title derived from the FAQ's question.
5. The server responds with a 301 Moved Permanently redirect to the generated URL, exposing the FAQ's title in the `Location` header.
6. The attacker records the 301 responses, extracting the FAQ's category, ID, language, and title from the `Location` header.
7. The attacker repeats steps 1-6, enumerating solution IDs to discover all FAQ entries, including those with restricted access.
8. The attacker gains knowledge of restricted FAQ titles, compromising confidentiality where titles contain sensitive information about the FAQ's content.

## Impact

Successful exploitation allows any unauthenticated visitor to enumerate all FAQ entries on the phpMyFAQ instance, including those intended for specific groups or users. The attacker can read the title of every restricted FAQ. For deployments that host internal-only content alongside public content (e.g., staff knowledge bases, internal SOPs, confidential customer notes), this leads to a loss of confidentiality. The slugified titles, often encoding the subject directly (e.g., `q3-layoff-plan`), expose sensitive information.

## Recommendation

*   Apply the recommended fix by adding a permission filter to `getIdFromSolutionId()` using `QueryHelper::queryPermission()` (see code snippet in the original advisory) to prevent unauthenticated access.
*   Remove the unconditional fallback in `getFaqBySolutionId()` at `Faq.php:1256-1265` to ensure permission checks are enforced.
*   Deploy the Sigma rule "phpMyFAQ Unauthenticated Solution ID Enumeration" to detect attackers enumerating `/solution_id_{id}.html` to discover restricted FAQ titles.
*   Monitor web server logs (category: webserver, product: linux) for HTTP 301 responses originating from requests to `/solution_id_{id}.html` as an indicator of potential exploitation.
