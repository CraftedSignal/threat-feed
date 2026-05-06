---
title: AVideo SSRF Vulnerability via HTTP Redirect and DNS Rebinding
slug: 2024-01-avideo-ssrf
description: AVideo is vulnerable to Server-Side Request Forgery (SSRF) due to improper validation of user-supplied URLs that does not prevent HTTP redirects, and DNS rebinding due to discarded resolved IP addresses.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - avideo
  - dns-rebinding
vendors:
  - wwbn
products:
  - aVideo (<= 29.0)
references:
  - https://github.com/advisories/GHSA-2hch-c97c-g99x
iocs:
  - type: domain
    value: rebind.attacker.com
ioc_counts:
  domain: 1
rules:
  - title: Detect AVideo SSRF Attempt via Internal IP in Request URI
    description: Detects potential SSRF attempts in AVideo by monitoring web server logs for requests containing internal IP addresses in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo SSRF Attempt via Redirect to Internal IP
    description: Detects potential SSRF attempts in AVideo by monitoring web server logs for 302 redirects to internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AVideo, version 29.0 and earlier, contains a Server-Side Request Forgery (SSRF) vulnerability due to insufficient validation of user-supplied URLs. Specifically, the `isSSRFSafeURL()` function, intended to prevent SSRF attacks, fails to account for HTTP redirects. This allows an attacker to bypass the intended security checks by providing a URL that initially appears safe but redirects to an internal resource, such as cloud metadata endpoints (169.254.169.254). Additionally, multiple callers of `isSSRFSafeURL()` discard the `$resolvedIP` parameter, creating a Time-of-Check Time-of-Use (TOCTOU) race condition exploitable via DNS rebinding. Attackers can manipulate DNS resolution to access internal services (127.0.0.1) that would otherwise be protected. Successful exploitation can lead to the disclosure of sensitive information, such as IAM credentials and internal service details.

## Attack Chain

1. Attacker crafts a malicious URL pointing to a server they control.
2. The attacker's server responds with a 302 redirect to an internal resource (e.g., `http://169.254.169.254/latest/meta-data/`).
3. The attacker submits the initial malicious URL to a vulnerable AVideo endpoint (e.g., `/plugin/AI/receiveAsync.json.php`).
4. The `isSSRFSafeURL()` function validates the initial URL, which resolves to a public IP address, and incorrectly passes the check.
5. The `file_get_contents()` function, without proper redirect restrictions, follows the 302 redirect to the internal resource.
6. The request is made to the internal resource, bypassing the intended SSRF protections.
7. The internal resource (e.g., cloud metadata) responds with sensitive information.
8. The sensitive information (e.g., IAM credentials) is stored as a video thumbnail or image within the application, accessible to the attacker.

## Impact

Successful exploitation of this SSRF vulnerability allows an authenticated attacker to force the AVideo server to make HTTP requests to arbitrary internal hosts. This includes cloud metadata endpoints (e.g., 169.254.169.254), potentially leading to the exfiltration of IAM credentials and instance identity information. Attackers can also access internal services on localhost (127.0.0.1) or the private network, such as databases, admin panels, and monitoring systems. The exfiltrated data can be retrieved through the application's public interface, increasing the severity of the impact.

## Recommendation

*   Apply the suggested fix by routing affected files through `url_get_contents()` to safely handle redirects, as detailed in the advisory.
*   As an alternative to using `url_get_contents()`, implement an explicit no-redirect context when calling `file_get_contents()` to prevent automatic redirect following.
*   Update all callers of `isSSRFSafeURL()` to capture the `$resolvedIP` parameter and pass it to a DNS-pinning-aware fetch function using `CURLOPT_RESOLVE` to mitigate DNS rebinding attacks.
*   Monitor web server logs for requests containing internal IP addresses (169.254.169.254, 127.0.0.1) in the URL, as these may indicate SSRF attempts.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
