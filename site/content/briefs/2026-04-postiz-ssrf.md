---
title: Postiz SSRF Vulnerability (CVE-2026-40168)
slug: 2026-04-postiz-ssrf
description: Postiz, an AI social media scheduling tool, is vulnerable to Server-Side Request Forgery (SSRF) in versions prior to 2.21.5, allowing attackers to access internal resources.
date: "2026-04-11T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - cve-2026-40168
  - postiz
cves:
  - id: CVE-2026-40168
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40168
  - https://github.com/gitroomhq/postiz-app/commit/30e8b777098157362769226d1b46d83ad616cb06
  - https://github.com/gitroomhq/postiz-app/releases/tag/v2.21.5
  - https://github.com/gitroomhq/postiz-app/security/advisories/GHSA-34w8-5j2v-h6ww
rules:
  - title: Detect Postiz SSRF Attempt via Public Stream Endpoint
    description: Detects potential SSRF attempts targeting the /api/public/stream endpoint in Postiz by identifying requests that redirect to internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect Postiz SSRF Initial Request
    description: Detects initial request to the /api/public/stream endpoint, which might be followed by a redirect to internal resources.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Postiz is an AI-powered social media scheduling tool. Versions prior to 2.21.5 are susceptible to a Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2026-40168. The vulnerability exists in the `/api/public/stream` endpoint. The application validates the initially supplied URL and blocks direct access to private or internal hosts. However, it fails to re-validate the final destination after HTTP redirects. This flaw enables an attacker to bypass the initial validation by providing a public HTTPS URL that redirects to an internal resource. Successful exploitation can lead to information disclosure, internal service enumeration, and potentially further compromise of the Postiz infrastructure. The vulnerability was reported and patched in version 2.21.5.

## Attack Chain

1. The attacker identifies the vulnerable `/api/public/stream` endpoint in Postiz.
2. The attacker crafts a malicious URL. This URL is a valid, publicly accessible HTTPS URL.
3. The malicious URL is designed to redirect the request to an internal resource (e.g., `http://127.0.0.1:8080/`).
4. The attacker submits the crafted URL to the `/api/public/stream` endpoint.
5. Postiz server-side application validates the initial URL, which passes because it's a public HTTPS address.
6. The Postiz server-side application follows the HTTP redirect from the attacker-controlled URL.
7. The request is redirected to the internal resource (e.g., `http://127.0.0.1:8080/`).
8. The Postiz server makes a request to the internal resource, potentially revealing sensitive information or enabling further exploitation.

## Impact

Successful exploitation of CVE-2026-40168 allows an attacker to perform Server-Side Request Forgery (SSRF) attacks against the Postiz application. This can lead to the exposure of sensitive internal resources, such as configuration files, internal APIs, or databases. An attacker might be able to enumerate internal services, read sensitive data, or even perform actions on behalf of the Postiz server. The severity of the impact depends on the nature of the accessible internal resources and could range from information disclosure to remote code execution.

## Recommendation

*   Upgrade Postiz to version 2.21.5 or later to patch CVE-2026-40168 as referenced in the Postiz release notes.
*   Implement strict URL validation and sanitization on the `/api/public/stream` endpoint. Ensure that validation occurs both before and after any HTTP redirects.
*   Deploy the Sigma rule to detect suspicious requests to the `/api/public/stream` endpoint that may indicate SSRF attempts.
*   Monitor web server logs for unusual HTTP requests originating from the Postiz server to internal IP addresses or private network ranges.
