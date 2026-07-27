---
title: Grav Remote Code Execution Vulnerability in Blueprint::dynamicData()
slug: 2026-07-grav-rce
description: A critical remote code execution vulnerability (CVE-2026-65008) in Grav versions prior to 2.0.7 allows an authenticated attacker with `admin.pages` or `api.pages.write` permissions to embed malicious callable directives in a page's frontmatter, leading to arbitrary code execution as the web-server user when the page is accessed.
date: "2026-07-21T12:21:53Z"
lastmod: "2026-07-27T14:01:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=3AE98397-A607-54E0-8D0E-35CF082FA7CE&utm_source=rss&utm_medium=rss
tags:
  - web-exploitation
  - rce
  - php
vendors:
  - Grav
products:
  - Grav < 2.0.7
  - Grav CMS (< 2.0.7)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Grav 2.0.4 ... contains a remote code execution vulnerability in Blueprint::dynamicData() ... The command then executes as the web-server user whenever anyone ... accesses the page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: Blueprint::dynamicData() ... passes a Class::method callable string and its arguments directly to call_user_func_array()
    confidence_band: high
cves:
  - id: CVE-2026-65008
    cvss: 9.8
    epss: 0.00648
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65008
  - https://sploitus.com/exploit?id=3AE98397-A607-54E0-8D0E-35CF082FA7CE&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=3AE98397-A607-54E0-8D0E-35CF082FA7CE
  - type: url
    value: https://github.com/getgrav/grav/security/advisories/GHSA-fj2p-qj2f-74v5
  - type: url
    value: https://nvd.nist.gov/vuln/detail/CVE-2026-65008
  - type: url
    value: https://vulners.com/cve/CVE-2026-65008
ioc_counts:
  url: 4
updates:
  - at: "2026-07-27T14:01:49Z"
    level: L2
    summary: poc_available; OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=3AE98397-A607-54E0-8D0E-35CF082FA7CE&utm_source=rss&utm_medium=rss
---

A critical remote code execution (RCE) vulnerability, identified as CVE-2026-65008, has been discovered in Grav versions prior to 2.0.7. The flaw resides within the `Blueprint::dynamicData()` function in `system/src/Grav/Common/Data/Blueprint.php`, which unsafely passes a `Class::method` callable string and its arguments directly to PHP's `call_user_func_array()` without proper validation or an allowlist. This oversight enables an authenticated attacker with `admin.pages` or `api.pages.write` permissions to inject a malicious callable directive into a page's frontmatter. Subsequently, when any user, including unauthenticated visitors, accesses the compromised page, the embedded malicious command executes on the web server with the privileges of the web-server user, allowing for arbitrary code execution.

## Attack Chain

1. An attacker gains authenticated access to a Grav installation with `admin.pages` or `api.pages.write` permissions.
2. The attacker accesses the Grav administration panel to create or modify an existing page.
3. The attacker embeds a malicious PHP callable string, such as `system('command')` or `exec('command')`, within the page's frontmatter definition.
4. The Grav application processes and stores the crafted page content, including the malicious callable directive.
5. Any user, whether authenticated or unauthenticated, navigates to and accesses the compromised Grav page via the web server.
6. During page rendering, the vulnerable `Blueprint::dynamicData()` function processes the page's frontmatter.
7. The function passes the attacker-controlled callable string and its arguments directly to `call_user_func_array()` without any sanitization or validation.
8. The malicious PHP code executes on the underlying web server with the privileges of the web-server user, granting the attacker arbitrary remote code execution capabilities.

## Impact

Successful exploitation of CVE-2026-65008 results in arbitrary remote code execution on the Grav host, with the privileges of the web-server user. This critical vulnerability (CVSS v3.1 Base Score: 9.8) grants attackers full control over the compromised Grav instance and potentially the underlying server. Impact could include website defacement, data exfiltration, installation of backdoors, further network penetration, or use of the server for malicious activities such as hosting malware or launching attacks. While no specific victim numbers or targeted sectors are detailed, any organization using affected Grav versions is at severe risk.

## Recommendation

* Patch Grav to version 2.0.7 or later immediately to remediate CVE-2026-65008.
* Regularly review user permissions in Grav, especially those with `admin.pages` or `api.pages.write`, to ensure the principle of least privilege is strictly enforced.
* Monitor web server access logs for unusual POST or PUT requests to Grav administration endpoints that create or modify page content, looking for suspicious embedded callable functions.
