---
title: Jupyter Server CORS Origin Validation Bypass via Regex
slug: 2024-01-jupyter-cors-bypass
description: Jupyter Server versions 2.17.0 and earlier are vulnerable to a CORS origin validation bypass due to improper use of `re.match()` in validating the Origin header against the `allow_origin_pat` configuration, allowing attackers to bypass CORS restrictions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cors
  - origin-validation
  - regex
  - web-application
vendors:
  - Jupyter
products:
  - jupyter-server (<= 2.17.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-24qx-w28j-9m6p
  - https://github.com/jupyter-server/jupyter_server/pull/603
  - https://docs.python.org/3/library/re.html#re.fullmatch
  - https://docs.python.org/3/library/re.html#re.match
rules:
  - title: Detect Jupyter Server CORS Bypass Attempt via Origin Header
    description: Detects potential CORS bypass attempts against Jupyter Server by monitoring the Origin header in web server logs for patterns that may indicate exploitation of CVE-2026-40110.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect Jupyter Server Regex Misconfiguration
    description: Detects potentially vulnerable Jupyter Server configurations by identifying instances where the allow_origin_pat setting is not properly anchored with ^ and $.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Jupyter Server, a web-based interactive development environment, is susceptible to a CORS (Cross-Origin Resource Sharing) bypass vulnerability. This flaw arises from the server's reliance on the `re.match()` function in Python's regular expression library for validating the `Origin` header against the configured `allow_origin_pat`. The `re.match()` function, unlike `re.fullmatch()`, only anchors the regex at the beginning of the string, not the end. Consequently, an attacker can craft a malicious domain, such as `http://trusted.example.com.evil.com/`, which will pass the regex validation if the `allow_origin_pat` is intended to match `trusted.example.com`. This vulnerability impacts Jupyter Server versions 2.17.0 and prior. The fix was implemented in pull request #603 and patched in commits 057869a327c46730afede3eab0ca2d2e3e74acea and 49b34392feaa97735b3b777e3baf8f22f2a14ed8. Successful exploitation allows an attacker to bypass CORS restrictions, potentially leading to unauthorized data access or actions on behalf of legitimate users.

## Attack Chain

1. An attacker identifies a Jupyter Server instance running version 2.17.0 or earlier.
2. The attacker crafts a malicious website with a domain name designed to bypass the `allow_origin_pat` regex. For instance, if the intended origin is `trusted.example.com`, the attacker uses `trusted.example.com.evil.com`.
3. A victim user visits the attacker's malicious website in their browser.
4. The malicious website sends a cross-origin HTTP request to the vulnerable Jupyter Server. The `Origin` header in the request is set to the attacker-controlled domain (`trusted.example.com.evil.com`).
5. The Jupyter Server receives the request and validates the `Origin` header against the `allow_origin_pat` configuration using `re.match()`.
6. Due to the behavior of `re.match()`, the attacker's origin passes the validation, as the regex only checks for a match at the beginning of the string.
7. The Jupyter Server processes the cross-origin request, effectively bypassing the intended CORS restrictions.
8. The attacker can then potentially perform unauthorized actions or access sensitive data within the Jupyter Server, as if the request originated from a trusted source.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass CORS restrictions on vulnerable Jupyter Server instances. This could lead to unauthorized access to sensitive data, modification of user settings, or execution of arbitrary code within the Jupyter environment, all performed under the guise of a legitimate user. The number of affected instances depends on the prevalence of vulnerable Jupyter Server versions and the use of misconfigured `allow_origin_pat` settings.

## Recommendation

*   Upgrade Jupyter Server to a version greater than 2.17.0, which includes the fix for CVE-2026-40110.
*   As a workaround, wrap your `allow_origin_pat` configuration value with `^` and `$` to ensure the regex matches the entire string, as suggested in the advisory.
*   Monitor web server logs for requests with `Origin` headers matching the pattern `trusted.example.com.*` (adjusting the `trusted.example.com` to your actual configured pattern) to detect potential exploitation attempts. Implement this detection using the provided Sigma rule targeting webserver logs.
