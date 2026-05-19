---
title: 'HAX open-apis: Credential Theft via Server-Side Request Forgery (SSRF) in open-apis'
slug: 2026-05-ssrf-in-open-apis
description: Multiple functions in open-apis conduct substring-only matching to validate hostnames, allowing an attacker to perform Server-Side Request Forgery (SSRF) and capture authentication credentials by redirecting requests to an attacker-controlled endpoint.
date: "2026-05-19T14:46:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - credential-theft
  - open-apis
vendors:
  - haxtheweb
products:
  - '@haxtheweb/open-apis'
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-4fg7-f244-3j49
  - https://github.com/haxtheweb/open-apis/blob/ff694ce91442c39ae1a78dc21e9ce50546aa207a/api/services/website/cacheAddress.js#L21
  - https://github.com/haxtheweb/open-apis/blob/ff694ce91442c39ae1a78dc21e9ce50546aa207a/api/apps/haxcms/lib/JOSHelpers.js#L26
  - https://github.com/haxtheweb/open-apis/blob/ff694ce91442c39ae1a78dc21e9ce50546aa207a/api/apps/haxcms/convert/elmslnToSite.js#L37
rules:
  - title: Detect SSRF via Substring Matching in open-apis
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in open-apis by identifying requests to external domains containing substrings of internal hostnames, indicating potential credential theft via vulnerable hostname validation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
  - title: Detect API calls to cacheAddress.js with suspicious domains
    description: Detects API calls that utilize the cacheAddress.js endpoint, potentially indicating a Server-Side Request Forgery (SSRF) attempt by leveraging substring validation vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The open-apis package by haxtheweb contains a vulnerability related to insufficient hostname validation. Specifically, the functions in `cacheAddress.js`, `JOSHelpers.js`, and `elmslnToSite.js` use substring matching to validate hostnames when deciding whether to send basic authorization headers. This flawed logic allows attackers to craft API calls that include a valid substring, but redirect the request to an attacker-controlled domain, effectively capturing the credentials intended for the legitimate domains. This vulnerability affects versions of `@haxtheweb/open-apis` prior to 26.0.0 and poses a risk of internal data and credential exfiltration.

## Attack Chain

1. The attacker identifies a vulnerable endpoint using `cacheAddress.js`, `JOSHelpers.js`, or `elmslnToSite.js`.
2. The attacker crafts a malicious API call to the vulnerable endpoint.
3. The API call includes a substring that matches a hard-coded, legitimate site name.
4. The attacker appends the matched substring to an attacker-controlled domain within the API call.
5. The vulnerable function performs a server-side request to the attacker-controlled domain.
6. The request includes authentication credentials intended for the legitimate domain.
7. The attacker captures the transmitted authentication credentials from their controlled server.
8. The attacker uses the stolen credentials to access unreleased LMS content on other systems.

## Impact

This vulnerability allows for the exfiltration of sensitive internal data, including authentication credentials. The captured credentials can grant unauthorized access to other systems, including unreleased LMS content. The vulnerability affects all users of `@haxtheweb/open-apis` versions prior to 26.0.0, with the impact being the potential compromise of internal systems and data.

## Recommendation

*   Upgrade the `@haxtheweb/open-apis` package to version 26.0.0 or later to patch the vulnerability as described in [GHSA-4fg7-f244-3j49](https://github.com/advisories/GHSA-4fg7-f244-3j49).
*   Deploy the Sigma rule "Detect SSRF via Substring Matching in open-apis" to identify attempts to exploit this vulnerability.
*   Review and audit internal APIs that handle sensitive credentials to ensure proper hostname validation is implemented to prevent similar SSRF attacks.
