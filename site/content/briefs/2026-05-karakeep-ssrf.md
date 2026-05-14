---
title: Karakeep SDK SSRF via metascraper-logo-favicon
slug: 2026-05-karakeep-ssrf
description: Karakeep SDK is vulnerable to SSRF via the `metascraper-logo-favicon` plugin, which bypasses intended SSRF protections by making HTTP requests to URLs extracted from attacker-controlled HTML `<link rel="icon">` tags, allowing authenticated users to trigger server-side requests to arbitrary internal URLs.
date: "2026-05-14T18:27:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - karakeep
  - metascraper
  - web-application
vendors:
  - npm
products:
  - '@karakeep/sdk (<= 0.31.0)'
  - got
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-7rx4-c5vx-g8w3
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect Karakeep SSRF to Internal IPs
    description: Detects HTTP requests originating from the Karakeep server to internal IP addresses, indicating potential SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - resource_development
    techniques:
      - T1190
      - T1592
    data_sources:
      - network_connection
      - windows
  - title: Detect Karakeep SSRF to AWS Metadata Endpoint
    description: Detects HTTP requests originating from Karakeep server to the AWS metadata endpoint (169.254.169.254), indicating potential SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - resource_development
    techniques:
      - T1190
      - T1592
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Karakeep SDK is vulnerable to Server-Side Request Forgery (SSRF) due to the `metascraper-logo-favicon` plugin (v5.49.5) not being subject to the application's `validateUrl()` function. This function, which is normally used to protect against SSRF, is bypassed when fetching favicon URLs from `<link rel="icon">` tags within HTML content. An attacker can exploit this by creating a bookmark with a URL pointing to a malicious page. This page contains `<link rel="icon">` tags with `href` attributes pointing to internal or private network addresses. When the server fetches the page, it will then make requests to these internal URLs without proper validation, potentially exposing sensitive information or allowing unauthorized access to internal resources. This vulnerability was introduced by the lack of validation in the `parseHtmlSubprocess.ts` file.

## Attack Chain

1.  Attacker crafts a malicious HTML page with `<link rel="icon">` tags containing internal or private IP addresses (e.g., `127.0.0.1`, `169.254.169.254`, `192.168.1.1`) in the `href` attribute.
2.  The attacker hosts this malicious HTML page on a publicly accessible server (e.g., `https://attacker.example.com/ssrf.html`).
3.  A Karakeep user, authenticated and authorized to create bookmarks, creates a new bookmark with the URL of the malicious HTML page.
4.  The Karakeep server fetches the HTML content of the bookmarked page using `fetchWithProxy()`. This initial request passes through the `validateUrl()` function, ensuring the main URL is a valid public address.
5.  The fetched HTML content is passed to the `parseHtmlSubprocess.ts` script, which utilizes `metascraper-logo-favicon` to parse the HTML and extract favicon URLs from the `<link rel="icon">` tags.
6.  `metascraper-logo-favicon` extracts the malicious URLs from the `href` attributes of the `<link rel="icon">` tags.
7.  The `reachable-url` library, wrapped by `got`, is used to make HTTP GET requests to the extracted favicon URLs *without* any SSRF validation.
8.  The Karakeep server makes HTTP GET requests to the attacker-specified internal or private IP addresses, bypassing the intended SSRF protections, potentially leaking sensitive information or allowing unauthorized access.

## Impact

Successful exploitation of this SSRF vulnerability allows an attacker to force the Karakeep server to make requests to internal services and resources. This can result in the exposure of sensitive information such as cloud metadata (e.g., AWS IAM credentials via `http://169.254.169.254/latest/meta-data/`), internal service discovery, and redirection-based data leaks. The application's intended SSRF protections are rendered ineffective, potentially leading to full compromise of the Karakeep instance and its associated data.

## Recommendation

*   Deploy the following Sigma rule to detect HTTP requests originating from the Karakeep server to internal IP addresses, indicating potential SSRF exploitation (log source: `network_connection`, rule title: "Detect Karakeep SSRF to Internal IPs").
*   Implement the suggested fix by adding URL validation hooks to the `gotOpts` within `metascraperLogo` in `apps/workers/scripts/parseHtmlSubprocess.ts`, ensuring that all favicon URLs are validated by `validateUrl()` before being requested.
*   Upgrade the `@karakeep/sdk` package to a version greater than 0.31.0 to incorporate any official patches addressing this vulnerability (affected product: `@karakeep/sdk`).
*   Monitor outbound network traffic from the Karakeep server for connections to internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and the AWS metadata endpoint (169.254.169.254) (IOCs).
