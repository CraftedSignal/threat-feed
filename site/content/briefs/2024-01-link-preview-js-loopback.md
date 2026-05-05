---
title: link-preview-js vulnerable to IPv6 and internal loopback attacks
slug: 2024-01-link-preview-js-loopback
description: link-preview-js versions 4.0.0 and earlier are vulnerable to IPv6 and internal loopback attacks, allowing potential internal data leaks by resolving addresses to internal IPs; patched in version 4.0.1.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - link-preview-js
  - loopback
  - ipv6
  - dns
  - internal-ip
products:
  - link-preview-js (<= 4.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-4gp8-rjrq-ch6q
rules:
  - title: Detect Outbound Connection to Internal IP Range
    description: Detects outbound network connections to internal IP address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) which may indicate exploitation of loopback/internal IP vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect DNS queries for internal TLDs
    description: Detects DNS queries for potentially malicious internal TLDs like .internal, .local, .nip.io, .sslip.io
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - dns_query
      - windows
  - title: Detect Process Accessing IPv6 Loopback Address
    description: Detects processes attempting to connect to the IPv6 loopback address (::1), which can be indicative of an attack targeting internal services via loopback.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

The `link-preview-js` library, versions 4.0.0 and earlier, is susceptible to IPv6 loopback and internal IP address resolution attacks. This vulnerability arises because the library lacks proper validation for IPv6 loopback addresses and fails to adequately prevent DNS resolution to internal IP addresses. An attacker could exploit this to potentially leak internal data by causing the library to fetch content from internal services. Version 4.0.1 addresses this vulnerability by tightening the regex used for validation for IPv6 addresses and prohibiting `.internal`, `.local`, `.nip.io` and `.sslip.io` addresses. Users are strongly encouraged to use the `resolveDNSHost` option to perform DNS resolution before fetching content.

## Attack Chain

1. An attacker crafts a URL that resolves to an internal IP address or an IPv6 loopback address.
2. The attacker provides the malicious URL to an application using the vulnerable `link-preview-js` library.
3. The `link-preview-js` library fetches the URL to generate a preview, without proper validation of the resolved IP address.
4. The library resolves the hostname, potentially using a DNS server controlled by the attacker or vulnerable to DNS poisoning.
5. The DNS resolution returns an internal IP address (e.g., 127.0.0.1, ::1, 192.168.x.x, 10.x.x.x, 172.16.x.x).
6. The library connects to the internal IP address, potentially accessing internal services or resources.
7. The application using `link-preview-js` processes the response from the internal service.
8. Sensitive internal data is leaked as part of the link preview generation process.

## Impact

Successful exploitation of this vulnerability could lead to the exposure of sensitive internal data. An attacker could potentially gain access to internal services, configuration files, or other resources that are not intended for public access. The specific impact depends on the nature of the internal services and data exposed. This vulnerability affects applications using `link-preview-js` version 4.0.0 or earlier, before the fix in version 4.0.1.

## Recommendation

*   Upgrade `link-preview-js` to version 4.0.1 or later to address the vulnerability.
*   Implement additional validation of URLs and IP addresses before passing them to `link-preview-js`.
*   Use the `resolveDNSHost` option to do DNS resolution before fetching content as suggested in the advisory.
*   Monitor network connections for outbound requests to internal IP address ranges originating from processes using `link-preview-js`. Deploy the `Detect Outbound Connection to Internal IP Range` Sigma rule to identify potential exploitation.
*   Implement the `Detect DNS queries for internal TLDs` Sigma rule to identify DNS queries for internal domains such as `.internal`, `.local`, `.nip.io` and `.sslip.io`.
*   Apply network segmentation and access controls to limit the exposure of internal services.
