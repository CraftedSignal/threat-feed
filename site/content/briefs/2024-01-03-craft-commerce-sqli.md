---
title: Craft Commerce Blind SQL Injection via hasVariant/hasProduct Properties
slug: 2024-01-03-craft-commerce-sqli
description: A blind SQL injection vulnerability exists in Craft Commerce's `ProductQuery::hasVariant` and `VariantQuery::hasProduct` properties, allowing authenticated control panel users to extract arbitrary database contents and potentially escalate privileges.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - craft-commerce
  - web-application
vendors:
  - Craft CMS
products:
  - Craft Commerce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-32272
references:
  - https://github.com/advisories/GHSA-r54v-qq87-px5r
rules:
  - title: Detect Craft Commerce SQL Injection Attempt via hasVariant
    description: Detects potential SQL injection attempts in Craft Commerce via the hasVariant parameter in the ElementIndexesController.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Craft Commerce SQL Injection Attempt via hasProduct
    description: Detects potential SQL injection attempts in Craft Commerce via the hasProduct parameter in the ElementIndexesController.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Keywords in URI Query
    description: Detects generic SQL injection keywords in URI queries, potentially related to Craft Commerce exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 3
---

A blind SQL injection vulnerability has been identified in Craft Commerce, specifically affecting the `ProductQuery::hasVariant` and `VariantQuery::hasProduct` properties. This vulnerability bypasses a blocklist implemented in `ElementIndexesController` (GHSA-2453-mppf-46cj) intended to prevent SQL injection attacks. The bypass occurs because the blocklist only filters top-level Yii2 Query properties, while `hasVariant` and `hasProduct` pass through without sanitization. These properties then call `Craft::configure()` on a subquery, reintroducing the SQL injection vulnerability via a crafted `criteria[hasVariant][where]=INJECTED_SQL` parameter. This flaw allows an authenticated user of the control panel to perform boolean-based blind SQL injection and extract sensitive information from the database. The vulnerability affects composer/craftcms/commerce versions 5.0.0 to before 5.6.0.

## Attack Chain

1.  Attacker authenticates to the Craft Commerce control panel.
2.  Attacker crafts a malicious HTTP request targeting the `ElementIndexesController`.
3.  The crafted request includes a `criteria[hasVariant][where]` parameter containing the SQL injection payload.
4.  The `ElementIndexesController` processes the request and calls the `hasVariant` or `hasProduct` property.
5.  `Craft::configure()` is invoked on a subquery without proper sanitization, injecting the malicious SQL.
6.  The database executes the injected SQL query, performing boolean-based comparisons.
7.  Attacker infers database content based on response times or boolean results, exfiltrating data bit by bit.
8.  Attacker extracts sensitive information like security keys to forge admin sessions, leading to full control.

## Impact

Successful exploitation of this vulnerability grants attackers full read access to the Craft Commerce database. This includes sensitive data such as user credentials, API keys, and financial information. By extracting the security key, an attacker can forge administrative sessions, leading to complete control over the compromised Craft Commerce instance. This could lead to data breaches, financial loss, and reputational damage. While the number of affected installations is unknown, any Craft Commerce installation with the Commerce plugin installed and products with variants created is potentially vulnerable.

## Recommendation

*   Upgrade `composer/craftcms/commerce` to version 5.6.0 or later to patch CVE-2026-32272.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts targeting the `ElementIndexesController`.
*   Monitor web server logs for suspicious requests containing `criteria[hasVariant][where]` or `criteria[hasProduct][where]` parameters with potentially malicious SQL syntax.
*   Implement web application firewall (WAF) rules to filter out requests containing SQL injection payloads in the `criteria[hasVariant][where]` and `criteria[hasProduct][where]` parameters.
