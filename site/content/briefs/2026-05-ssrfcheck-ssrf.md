---
title: ssrfcheck vulnerable to SSRF via IPv4-mapped IPv6 bypass
slug: 2026-05-ssrfcheck-ssrf
description: ssrfcheck version 1.3.0 and earlier is vulnerable to server-side request forgery (SSRF) attacks because it fails to block private IP addresses encoded as IPv4-mapped IPv6 addresses due to WHATWG URL parsing.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - node.js
vendors:
  - npm
products:
  - ssrfcheck (<= 1.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-j4rj-2jr5-m439
iocs:
  - type: url
    value: http://[::ffff:127.0.0.1]/
  - type: url
    value: http://[::ffff:169.254.169.254]/
  - type: url
    value: http://[::ffff:192.168.1.1]/
  - type: url
    value: http://[::ffff:10.0.0.1]/
  - type: url
    value: http://[::ffff:172.16.0.1]/
  - type: url
    value: http://[::ffff:7f00:1]/
  - type: url
    value: http://[0:0:0:0:0:ffff:127.0.0.1]/
ioc_counts:
  url: 7
rules:
  - title: Detect SSRF Attempt via IPv4-mapped IPv6 Address
    description: Detects potential SSRF attempts by identifying HTTP requests containing IPv4-mapped IPv6 addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SSRF Attempt via HTTP Host Header
    description: Detects potential SSRF attempts by identifying HTTP Host header containing IPv4-mapped IPv6 addresses.
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

The `ssrfcheck` library, version 1.3.0 and earlier, contains a critical vulnerability that allows attackers to bypass its SSRF protection mechanisms. The vulnerability stems from the library's failure to properly handle IPv4 addresses encoded as IPv4-mapped IPv6 addresses (e.g., `http://[::ffff:127.0.0.1]/`). The WHATWG URL parser, which is integrated into Node.js, normalizes the IPv4 notation inside the brackets to a compressed hex form before `ssrfcheck`'s private IP regex is executed. This normalization bypasses the regex, which is designed to match dot-notation only. As a result, applications using the `isSSRFSafeURL()` function are exposed to SSRF attacks, potentially allowing attackers to access cloud metadata, internal network resources, and localhost services. This vulnerability affects all Node.js versions greater than or equal to 10.

## Attack Chain

1. The attacker identifies an application using `ssrfcheck` for URL validation.
2. The attacker crafts a malicious URL containing a private IP address encoded as an IPv4-mapped IPv6 address, such as `http://[::ffff:127.0.0.1]/`.
3. The application receives the URL from an untrusted source (e.g., user input, API parameter, webhook payload).
4. The application calls `isSSRFSafeURL()` to validate the URL.
5. The WHATWG URL parser normalizes the IPv4 notation inside the brackets (e.g., `127.0.0.1` becomes `7f00:1`).
6. The `isPrivateIP` function attempts to match the normalized IP address against its regex, but the regex fails because it expects dot notation.
7. `isSSRFSafeURL()` returns true, indicating that the URL is safe.
8. The application makes an HTTP request to the attacker-controlled URL, leading to SSRF. The attacker can now access internal resources, cloud metadata, or localhost services.

## Impact

Successful exploitation of this SSRF vulnerability can lead to significant security breaches. An attacker can potentially steal cloud metadata from AWS, GCP, or Azure instances by sending a request to `http://[::ffff:169.254.169.254]/latest/metadata`. This metadata often contains sensitive information such as API keys and credentials. The attacker can also pivot to internal network resources that are not exposed to the internet, accessing services on `10.x.x.x`, `172.16.x.x`, or `192.168.x.x`. Furthermore, the attacker can access services bound to loopback on the server, such as administrative interfaces at `http://[::ffff:127.0.0.1]/admin`. The bypass requires no authentication, special privileges, or non-default configurations. This vulnerability affects every version of `ssrfcheck` on every Node.js version >= 10, creating a widespread risk for applications relying on this library for SSRF protection.

## Recommendation

*   Upgrade to a patched version of `ssrfcheck` that addresses this vulnerability.
*   As a workaround, implement a custom URL validation function that explicitly checks for IPv4-mapped IPv6 addresses and blocks them before calling `isSSRFSafeURL()`.
*   Monitor application logs for suspicious outbound HTTP requests to private IP addresses or cloud metadata endpoints.
*   Deploy the Sigma rule `Detect SSRF Attempt via IPv4-mapped IPv6 Address` to detect potential SSRF attempts in web server logs.
*   Block the IOCs listed in this brief at the network or application level to prevent attackers from exploiting this vulnerability.
