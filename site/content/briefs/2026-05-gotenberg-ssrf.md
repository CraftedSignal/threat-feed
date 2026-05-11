---
title: Gotenberg SSRF via Chromium URL Endpoint with Redirect Bypass
slug: 2026-05-gotenberg-ssrf
description: Gotenberg's Chromium URL-to-PDF conversion endpoint is vulnerable to SSRF due to a lack of default protection against HTTP/HTTPS-based requests, allowing attackers to target internal IPs and cloud metadata endpoints, which can be bypassed via HTTP redirects.
date: "2026-05-11T13:51:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - gotenberg
  - cve-2026-42595
  - cloud-metadata
vendors:
  - GitHub
products:
  - Gotenberg/v8 (< 8.32.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery
references:
  - https://github.com/advisories/GHSA-chwh-f6gm-r836
  - https://github.com/advisories/GHSA-pjrr-jgp4-v2fm
  - https://github.com/advisories/GHSA-pcrp-7g9h-7qhp
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect Gotenberg SSRF via Chromium URL Endpoint
    description: Detects CVE-2026-42595 exploitation — SSRF attempts via Gotenberg's Chromium URL endpoint by monitoring HTTP POST requests with suspicious URLs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
  - title: Detect Gotenberg SSRF Redirect Bypass
    description: Detects Gotenberg SSRF redirect bypass attempts by monitoring for connections to potential redirect servers.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability exists in Gotenberg, an open-source PDF conversion tool. Specifically, the Chromium URL-to-PDF conversion endpoint (`/forms/chromium/convert/url`) lacks default protection against HTTP/HTTPS-based SSRF, while the default deny-list only blocks `file://` URIs. This allows unauthenticated attackers to target internal IPs, RFC 1918 ranges, and cloud metadata endpoints, receiving the response rendered as a PDF. Furthermore, even when operators configure a custom deny-list, the protection is bypassed via HTTP redirects. The Gotenberg instance follows `302` redirects from attacker-controlled external URLs to internal targets without re-validating the redirect destination against the deny-list. Version 8.30.1 of Gotenberg is confirmed to be vulnerable.

## Attack Chain

1.  The attacker identifies a Gotenberg instance accessible over the network, which requires no authentication by default.
2.  The attacker crafts a malicious HTTP POST request to the `/forms/chromium/convert/url` endpoint.
3.  The POST request includes a `url` parameter pointing to an internal resource (e.g., `http://127.0.0.1:3000/health` or `http://169.254.169.254/latest/meta-data/`).
4.  Alternatively, the POST request includes a `url` parameter pointing to an external redirect server (e.g., `http://172.17.0.1:9999/`).
5.  If using a redirect, the external server responds with a `302` redirect to an internal target (e.g., `http://127.0.0.1:3000/health`).
6.  The Gotenberg server, using a headless Chromium instance, fetches the URL (or follows the redirect) without proper validation.
7.  The response from the internal resource is rendered as a PDF document.
8.  The PDF document containing the sensitive information is returned to the attacker. The attacker exfiltrates the data.

## Impact

Successful exploitation allows an attacker to make the Gotenberg server fetch arbitrary internal resources and receive the rendered content as a PDF. This can lead to cloud credential theft by accessing cloud metadata endpoints, internal service access by reaching admin panels or databases, and internal port scanning. The redirect bypass further exacerbates the risk, rendering custom deny-lists ineffective. This vulnerability affects Gotenberg deployments that have broad internal network access.

## Recommendation

*   Deploy the Sigma rule `Detect Gotenberg SSRF via Chromium URL Endpoint` to identify attempts to exploit this vulnerability by monitoring for HTTP POST requests to the `/forms/chromium/convert/url` endpoint with potentially malicious URLs.
*   Deploy the Sigma rule `Detect Gotenberg SSRF Redirect Bypass` to detect connections to external redirect servers that may be used to bypass SSRF protections.
*   Upgrade Gotenberg to version 8.32.0 or later to patch CVE-2026-42595.
*   Implement network segmentation to limit the Gotenberg instance's access to internal resources, mitigating the impact of a successful SSRF attack.
*   Configure a custom deny-list on the Chromium URL endpoint to explicitly block access to internal IPs, RFC 1918 ranges, and cloud metadata endpoints.
