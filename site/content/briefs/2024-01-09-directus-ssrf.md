---
title: Directus SSRF Vulnerability via IPv4-Mapped IPv6 Addresses
slug: 2024-01-09-directus-ssrf
description: Directus versions before 11.16.0 are vulnerable to Server-Side Request Forgery (SSRF) due to a bypass in IP address validation using IPv4-Mapped IPv6 addresses, allowing attackers to access internal services and sensitive cloud metadata.
date: "2024-01-09T12:00:00Z"
lastmod: "2026-07-20T21:49:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - directus
  - vulnerability
vendors:
  - Directus
products:
  - Directus <= 12.0.0
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-wv3h-5fx7-966h
  - https://github.com/advisories/GHSA-j5h6-vqc3-phqh
iocs:
  - type: ip
    value: 0.0.0.0
  - type: ip
    value: 169.254.169.254
  - type: url
    value: http://0.0.0.0:8055/
ioc_counts:
  ip: 2
  url: 1
rules:
  - title: Detect Directus SSRF Attempt via IPv4-Mapped IPv6 Address
    description: Detects attempts to exploit the Directus SSRF vulnerability (CVE-2026-35409) by using IPv4-Mapped IPv6 addresses in file import requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Directus SSRF Attempt via IPv4-Mapped IPv6 Address in URI Path
    description: Detects attempts to exploit the Directus SSRF vulnerability (CVE-2026-35409) by using IPv4-Mapped IPv6 addresses in the request URI path.
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
updates:
  - at: "2026-07-20T21:49:53Z"
    level: L1
    summary: OS linux; OS macos
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-j5h6-vqc3-phqh
---

Directus, a headless CMS, is susceptible to an SSRF vulnerability (CVE-2026-35409) affecting versions prior to 11.16.0. This flaw allows attackers to bypass the intended IP deny-list by utilizing IPv4-Mapped IPv6 addresses. The vulnerability stems from the application's failure to properly normalize these addresses before validating them against the deny-list. This means an attacker can craft requests that appear to originate from a safe, external source, while the underlying system resolves the request to an internal resource. This vulnerability could be exploited by authenticated users or, in cases where public file import is enabled, by unauthenticated users. This issue was addressed in Directus version 11.16.0.

## Attack Chain

1. An attacker identifies a Directus instance running a version prior to 11.16.0.
2. The attacker authenticates to the Directus instance (or exploits public file import functionality if enabled).
3. The attacker crafts a malicious request to import a file, specifying a target IP address using an IPv4-Mapped IPv6 address (e.g., `::ffff:127.0.0.1` for localhost). This is done through the file import mechanism in Directus.
4. Directus's IP deny-list validation logic fails to properly normalize the IPv6 address. The check does not recognize the IPv6 form as representing a blocked IPv4 address.
5. The request bypasses the deny-list.
6. The underlying HTTP client within Directus resolves the IPv6 address to its IPv4 equivalent.
7. The request is sent to the internal service or cloud metadata endpoint specified in the IPv4-Mapped IPv6 address.
8. The attacker receives the response from the internal service, potentially containing sensitive information like database credentials, cached data, internal API responses, or cloud instance metadata.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-35409) can lead to the exposure of sensitive internal resources. An attacker could potentially access databases, caches, internal APIs, or cloud instance metadata. The impact includes potential data breaches, privilege escalation within the internal network, and unauthorized access to cloud resources. Given the potential access to cloud instance metadata, attackers could gain access to AWS, GCP, or Azure environments. The number of vulnerable Directus instances is unknown, but any unpatched instance is at risk.

## Recommendation

*   Upgrade Directus to version 11.16.0 or later to remediate the vulnerability as described in the overview.
*   Implement a web application firewall (WAF) rule to block requests containing IPv4-Mapped IPv6 addresses in file import requests to mitigate potential exploitation, even if the Directus instance is patched. Focus on filtering `cs-uri-query` and `cs-uri-path` for patterns like "::ffff:".
*   Monitor web server logs (`category: webserver`, `product: linux`) for requests containing IPv4-Mapped IPv6 addresses targeting internal resources. Create a Sigma rule to detect such patterns in cs-uri-query or cs-uri-path fields.
