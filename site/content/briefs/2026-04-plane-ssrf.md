---
title: Plane Project Management Tool SSRF Vulnerability (CVE-2026-39843)
slug: 2026-04-plane-ssrf
description: Plane project management tool versions before 1.3.0 are vulnerable to Server-Side Request Forgery (SSRF), allowing authenticated low-privilege attackers to read internal resources by exploiting the favicon fetch functionality.
date: "2026-04-09T16:16:31Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - cve-2026-39843
  - plane
  - project-management
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-39843
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39843
rules:
  - title: Detect Plane SSRF via Internal IP Request
    description: Detects potential SSRF attempts in Plane by monitoring for HTTP requests to internal IP addresses originating from the Plane application.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect Plane SSRF via Redirect to Internal IP
    description: Detects potential SSRF attempts in Plane by monitoring for HTTP redirects to internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Plane is an open-source project management tool. Versions prior to 1.3.0 are vulnerable to a Server-Side Request Forgery (SSRF) vulnerability, tracked as CVE-2026-39843. This vulnerability stems from an incomplete fix for GHSA-jcc6-f9v6-f7jw. An authenticated attacker with low privileges can exploit this vulnerability by supplying a crafted HTML page containing a `<link>` tag that redirects to a private IP address when using the "Add link" functionality. The vulnerability exists within the `fetch_and_encode_favicon()` function, which uses `requests.get(favicon_url, ...)` and follows redirects by default. This allows the attacker to force the server to make requests to internal resources. The vulnerability is resolved in version 1.3.0.

## Attack Chain

1.  Attacker authenticates to a Plane instance with low-privilege credentials.
2.  Attacker crafts a malicious HTML page containing a `<link>` tag in the `<head>` section. The `href` attribute of this tag points to a redirect URL.
3.  The redirect URL points to a private IP address or internal service (e.g., `http://192.168.1.100/`).
4.  The attacker uses the "Add link" functionality in Plane to add the crafted HTML page's URL to a project or task.
5.  Plane's `fetch_and_encode_favicon()` function attempts to fetch the favicon from the supplied URL.
6.  Due to the redirect in the malicious HTML page, the server-side request is redirected to the private IP address specified in the `href` attribute.
7.  The server fetches content from the internal resource.
8.  The attacker can view the response from the internal resource, potentially revealing sensitive information or allowing further exploitation.

## Impact

Successful exploitation of this SSRF vulnerability allows an authenticated, low-privilege attacker to read internal resources that the Plane server has access to. This could lead to the exposure of sensitive data, such as configuration files, internal API endpoints, or other confidential information. The number of potential victims is equal to the number of organizations using vulnerable versions of the Plane project management tool. The severity of the impact depends on the sensitivity of the information exposed and the attacker's ability to leverage the exposed information for further attacks.

## Recommendation

*   Upgrade Plane to version 1.3.0 or later to patch CVE-2026-39843.
*   Monitor web server logs for requests originating from the Plane application to internal IP addresses, especially those in the private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Use the Sigma rule `Detect Plane SSRF via Internal IP Request` to identify such requests.
*   Implement network segmentation and restrict the Plane server's access to only necessary internal resources.
*   Consider implementing additional input validation and sanitization measures to prevent the injection of malicious URLs.
