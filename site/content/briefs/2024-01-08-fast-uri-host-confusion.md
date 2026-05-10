---
title: fast-uri Host Confusion Vulnerability via Percent-Encoded Authority Delimiters (CVE-2026-6322)
slug: 2024-01-08-fast-uri-host-confusion
description: The fast-uri library is vulnerable to host confusion due to improper handling of percent-encoded authority delimiters within the host component, potentially leading to redirection to unintended authorities.
date: "2026-05-08T19:13:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - host-confusion
  - url-parsing
  - fast-uri
  - cve-2026-6322
products:
  - fast-uri (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-6322
    cvss: 7.5
    epss: 0.00029
references:
  - https://github.com/advisories/GHSA-v39h-62p7-jpjc
rules:
  - title: Detect fast-uri Host Confusion Attempt
    description: Detects CVE-2026-6322 exploitation attempt — HTTP requests containing percent-encoded authority delimiters in the URI, potentially indicating host confusion attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect fast-uri Host Confusion Attempt - POST Request
    description: Detects CVE-2026-6322 exploitation attempt via POST — HTTP POST requests containing percent-encoded authority delimiters in the URI, potentially indicating host confusion attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

The `fast-uri` library, versions 3.1.1 and earlier, is susceptible to a host confusion vulnerability. The vulnerability stems from the library's incorrect decoding of percent-encoded authority delimiters (`%40` as `@`, `%3A` as `:`) inside the host component of a URI. This leads to the delimiters being serialized back as raw characters, effectively altering the URI structure. An attacker can exploit this by crafting a malicious URL where a hostname is converted into userinfo plus a different host. This is a critical issue because applications that rely on `fast-uri` for URL normalization before implementing security checks like host allowlisting, redirect validation, or outbound request routing can be tricked into directing users or requests to a malicious destination. This vulnerability is identified as CVE-2026-6322.

## Attack Chain

1. An attacker crafts a malicious URL containing a percent-encoded authority delimiter (e.g., `%40`) within the host part of the URL.
2. The victim application uses the vulnerable `fast-uri` library (version 3.1.1 or earlier) to parse and normalize the crafted URL.
3. `fast-uri` decodes the percent-encoded delimiter, replacing it with its raw character equivalent (e.g., `%40` becomes `@`).
4. The normalized URL's structure is altered, causing the host component to be misinterpreted. For example, `http://trusted.com%40evil.com/` becomes `http://trusted.com@evil.com/`.
5. The application's security checks, such as host allowlisting or redirect validation, are performed on the modified URL.
6. Due to the altered host component, the security checks pass, even though the intended destination is malicious. In the example above, the host check would evaluate `evil.com` rather than `trusted.com`.
7. The application redirects the user or routes the request to the attacker-controlled host (`evil.com` in the example).
8. The attacker can then perform malicious actions, such as phishing, serving malware, or stealing sensitive information.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass security checks in applications that rely on the vulnerable `fast-uri` library for URL normalization. This can lead to redirection to malicious sites, potentially affecting any application that uses the library for URL parsing and validation, including web browsers, web servers, and other network applications. The number of potential victims is dependent on the adoption rate of the vulnerable `fast-uri` library. If exploited, the attacker could perform a wide range of malicious activities, from credential harvesting to serving malware.

## Recommendation

*   Upgrade the `fast-uri` library to version 3.1.2 or later to patch CVE-2026-6322.
*   Deploy the Sigma rule "Detect fast-uri Host Confusion Attempt" to your SIEM and tune for your environment, focusing on `cs-uri` containing encoded delimiters.
*   Enable webserver logging for cs-uri to ensure accurate detection of malicious URLs.
