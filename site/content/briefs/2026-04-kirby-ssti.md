---
title: Kirby CMS Server-Side Template Injection via Double Template Resolution
slug: 2026-04-kirby-ssti
description: A server-side template injection (SSTI) vulnerability exists in Kirby CMS within the option rendering feature due to double template resolution in option fields (checkboxes, color, multiselect, select, radio, tags, or toggles) when using options from a query or API with untrusted values, potentially allowing attackers to inject malicious queries.
date: "2026-04-23T21:24:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssti
  - kirby
  - template-injection
vendors:
  - getkirby
products:
  - cms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-jcjw-58rv-c452
rules:
  - title: Detect Kirby CMS SSTI Attempt via HTTP Request
    description: Detects potential SSTI attempts in Kirby CMS by identifying HTTP requests containing template syntax in the query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Kirby CMS SSTI Attempt via POST Request Body
    description: Detects potential SSTI attempts in Kirby CMS by identifying POST requests containing template syntax in the body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side template injection (SSTI) vulnerability has been identified in Kirby CMS affecting sites using option fields (checkboxes, color, multiselect, select, radio, tags, or toggles) with options sourced from queries or APIs where the values cannot be fully trusted. This vulnerability, discovered and reported by @offset, stems from a double resolution of templates within the options rendering logic. An attacker with Panel access or through user interaction can inject malicious query templates. This can lead to unauthorized access to sensitive information (like user passwords) or malicious modification of site content. The vulnerability affects Kirby CMS versions prior to 4.9.0 and versions between 5.0.0 and 5.4.0.

## Attack Chain

1. An attacker gains access to the Kirby Panel, or convinces a user with access to interact with a malicious element.
2. The attacker identifies a page or blueprint using dynamic options for form fields (checkboxes, selects, etc.) sourced from a query or API.
3. The attacker injects a malicious query template, such as `{{ users.first.password }}` or `{{ page.delete }}`, into a page title or data returned from an external API.
4. The administrator or another privileged user navigates to the affected Panel view, triggering the rendering of the form field with the injected malicious template.
5. The Kirby CMS options logic improperly double-resolves the template, executing the injected query.
6. The attacker gains access to sensitive information, such as user passwords, or triggers unauthorized actions like page deletion, depending on the injected query.
7. The attacker escalates privileges by exploiting the compromised user's session or by directly accessing sensitive information.

## Impact

Successful exploitation of this vulnerability could allow attackers to access sensitive site information, such as user credentials, or perform unauthorized actions, like modifying or deleting content. This could lead to a complete compromise of the Kirby CMS website and its data. The vulnerability specifically targets sites that leverage dynamic options for form fields, making them susceptible to malicious query injection. Sites running vulnerable versions of Kirby CMS are at risk of information disclosure and unauthorized modification.

## Recommendation

*   Upgrade to Kirby CMS version 4.9.0 or 5.4.0 or later to patch the vulnerability as described in the advisory ([https://github.com/advisories/GHSA-jcjw-58rv-c452](https://github.com/advisories/GHSA-jcjw-58rv-c452)).
*   Apply input validation and sanitization to all data sources used for dynamic options to prevent the injection of malicious templates and mitigate CVE-2026-34587.
*   Monitor web server logs for suspicious activity, such as requests containing template syntax or attempts to access sensitive information, to identify potential exploitation attempts.
