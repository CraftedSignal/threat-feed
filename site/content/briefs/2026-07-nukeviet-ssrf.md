---
title: NukeViet Server-Side Request Forgery via X-Forwarded-Host (CVE-2026-55372)
slug: 2026-07-nukeviet-ssrf
description: An unauthenticated attacker can exploit a Server-Side Request Forgery (SSRF) vulnerability in NukeViet by spoofing the X-Forwarded-Host and X-Forwarded-Proto HTTP headers, allowing the server to make a cURL request to an attacker-controlled host without validation for internal host/port discovery and cache poisoning. The vulnerability affects NukeViet versions prior to 4.6.00.
date: "2026-07-13T18:02:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - web-vulnerability
  - nukeviet
vendors:
  - NukeViet
products:
  - nukeviet < 4.6.00
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can coerce the server into issuing HTTP requests to an attacker-chosen host... requires no authentication.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Scanning
    evidence: 'What an attacker can do: unauthenticated internal host/port discovery (connection success/timing, with the port reachable through the regex bypass)'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4chg-4752-w88r
---

A pre-authentication Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2026-55372, exists in NukeViet versions prior to 4.6.00. This flaw allows an unauthenticated attacker to manipulate the `X-Forwarded-Host` and `X-Forwarded-Proto` HTTP headers, coercing the NukeViet server into initiating outbound cURL requests to an attacker-specified internal or external host. The vulnerability resides within the `server_info_update()` function in `includes/ini.php`, where attacker-controlled header values are used without proper validation to construct a URL. Exploitation is triggered by a POST request to `index.php` containing the `__serverInfoUpdate=1` parameter, which is processed early in the application lifecycle before authentication. Although the SSRF is blind and uses a fixed request path, it can be abused for internal network reconnaissance (host and port discovery) and potentially to poison the site's cached `server_headers`.

## Attack Chain

1. An unauthenticated attacker crafts a `POST` request targeting `index.php` on the vulnerable NukeViet instance.
2. The attacker includes the `__serverInfoUpdate=1` field in the `POST` body and manipulates the `X-Forwarded-Host` and `X-Forwarded-Proto` HTTP headers with an attacker-controlled host (e.g., `127.0.0.1:8080/`).
3. The `includes/ini.php` file processes the `__serverInfoUpdate=1` trigger very early, before any authentication takes place.
4. The `NukeViet\Core\Server` component, specifically `standardizeHost()`, parses the `X-Forwarded-Host` and `X-Forwarded-Proto` headers, failing to properly validate or normalize the input. The specific bypass involves appending a slash to the host:port (e.g., `127.0.0.1:8080/`), preventing stripping of the port.
5. The `server_info_update()` function then concatenates the attacker-controlled protocol and host values directly into a URL string.
6. A cURL request is initiated by the NukeViet server to the constructed URL (e.g., `http://attacker-controlled-host:port/index.php?response_headers_detect=1`).
7. The NukeViet server performs an outbound network connection to the attacker-controlled host, allowing for out-of-band detection by the attacker.
8. The attacker can then use connection success/timing to perform internal host/port discovery or attempt to poison cached `server_headers` with the target's response.

## Impact

This SSRF vulnerability, while not allowing direct data exfiltration or cloud credential theft due to its blind, HEAD-only, and fixed-path nature, still poses significant risks. Attackers can leverage it for unauthenticated internal network reconnaissance, allowing them to map internal hosts and open ports within an organization's infrastructure. Furthermore, the vulnerability enables the poisoning of the site's `server_headers` cache, which could potentially lead to further, unspecified malicious activity if these headers are used to influence site behavior or user interactions. The CVSS v3.1 score is 7.2 (High), reflecting the network-exploitable, low-complexity nature without requiring user interaction.

## Recommendation

* Patch NukeViet installations to version 4.6.00 or later to remediate CVE-2026-55372, which includes robust validation and normalization of forwarded headers.
* Configure reverse proxies or web servers (e.g., Apache, Nginx) to strip or override client-supplied `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Port` headers.
* Ensure the `my_domains` configuration in NukeViet is set up with the site's canonical domain(s) to enable defense-in-depth checks.
* Monitor your web server access logs for `POST` requests to `/index.php` containing the `__serverInfoUpdate=1` parameter as this indicates attempted exploitation of CVE-2026-55372.
* Monitor network connection logs from your web server processes (e.g., `php-fpm`, `apache2`, `nginx`) for unusual outbound HTTP/HTTPS connections to external or internal IP addresses that are not part of legitimate application traffic.
