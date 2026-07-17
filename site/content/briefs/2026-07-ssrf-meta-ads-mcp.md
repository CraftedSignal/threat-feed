---
title: Unauthenticated Server-Side Request Forgery in meta-ads-mcp via image_url
slug: 2026-07-ssrf-meta-ads-mcp
description: An unauthenticated remote attacker can exploit a Server-Side Request Forgery (SSRF) vulnerability in `meta-ads-mcp` v1.0.113, specifically within the `upload_ad_image` function, by providing a malicious `image_url` parameter that causes the server to make arbitrary outbound HTTP requests to internal services, RFC 1918 addresses, or cloud metadata endpoints, leading to information disclosure and potential internal network compromise.
date: "2026-07-17T18:48:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - web
  - python
  - unauthenticated
vendors:
  - Meta
products:
  - meta-ads-mcp 1.0.113
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: When the server is deployed with the `streamable-http` transport...an unauthenticated remote attacker can supply an arbitrary URL...and cause the server to issue an outbound HTTP request to that target.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Any party capable of sending a JSON-RPC `tools/call` request to the MCP HTTP endpoint...can instruct the server to make arbitrary outbound HTTP GET requests, including to...Localhost services...RFC 1918 / private network addresses...
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1589
    technique_name: Gather Victim Identity Information
    evidence: cloud metadata endpoints such as `http://169.254.169.254/` (AWS IMDSv1, GCP, Azure), potentially exposing IAM credentials, instance identity documents, and bootstrap secrets
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-45gf-fjxp-cjpq
iocs:
  - type: url
    value: http://169.254.169.254/latest/meta-data/
  - type: url
    value: http://attacker.com/redirect
ioc_counts:
  url: 2
---

A critical Server-Side Request Forgery (SSRF) vulnerability has been identified in `meta-ads-mcp` version 1.0.113, affecting the `upload_ad_image` function. This flaw allows an unauthenticated remote attacker to coerce the server into making arbitrary HTTP GET requests to internal or external network targets. The vulnerability stems from the `image_url` parameter within the `upload_ad_image` tool, which is passed directly to an `httpx.AsyncClient` without any scheme, host, or IP address validation. Crucially, the authorization middleware only requires a non-empty Bearer token, meaning the SSRF is triggered before any meaningful Meta API credential validation occurs. This permits attackers to access localhost services, private network ranges (RFC 1918), and cloud instance metadata endpoints (e.g., `http://169.254.169.254/`), with a CVSS 3.1 Base Score of 8.3 (High). The issue specifically manifests when the server is deployed using the officially supported `--transport streamable-http` mode.

## Attack Chain

1. An unauthenticated attacker sends a JSON-RPC `initialize` request to the `meta-ads-mcp` `/mcp` endpoint, including a non-empty `Authorization: Bearer` token.
2. The attacker sends a subsequent JSON-RPC `tools/call` request to the same `/mcp` endpoint, specifying `upload_ad_image` as the tool to execute.
3. Within the `tools/call` request's `arguments` field, the attacker includes a crafted `image_url` parameter pointing to an internal target (e.g., `http://127.0.0.1:9009/poc.jpg`, `http://169.254.169.254/latest/meta-data/`).
4. The `meta-ads-mcp` application's authorization middleware verifies only the presence of a non-empty Bearer token in the `Authorization` header, allowing the request to proceed to the image download logic.
5. The application passes the attacker-controlled `image_url` directly to the `try_multiple_download_methods` function in `meta_ads_mcp/core/ads.py`.
6. An `httpx.AsyncClient` instance, configured to `follow_redirects=True`, initiates an outbound HTTP GET request to the arbitrary URL provided in `image_url` without any prior scheme, host, or IP address validation.
7. The `meta-ads-mcp` server establishes a connection and performs the GET request against the specified internal or cloud resource.
8. The server then attempts to perform Meta API credential validation, but the Server-Side Request Forgery has already successfully occurred.

## Impact

This Server-Side Request Forgery (SSRF) vulnerability allows an attacker to compel the vulnerable `meta-ads-mcp` server to initiate arbitrary HTTP GET requests. The primary impact is information disclosure, as an attacker can access sensitive data from internal network services, private IP ranges (RFC 1918), or cloud instance metadata endpoints (e.g., `http://169.254.169.254/`). This could expose highly confidential information such as IAM credentials, instance identity documents, bootstrap secrets, and internal network architecture details. Additionally, an attacker could use this vulnerability for internal network reconnaissance, mapping out accessible services, and potentially triggering state-changing actions on internal systems or causing limited denial of service by overwhelming internal targets. Organizations running `meta-ads-mcp` with the `--transport streamable-http` option in environments co-located with sensitive resources are at direct risk of compromise.

## Recommendation

* Patch `meta-ads-mcp` to a version higher than 1.0.113 immediately, as this vulnerability has been disclosed.
* Monitor network traffic for outbound HTTP GET requests from `meta-ads-mcp` instances to unusual internal IP addresses (RFC 1918, localhost) or cloud metadata endpoints like `169.254.169.254`, which could indicate attempted exploitation.
* Implement egress filtering on firewalls to restrict `meta-ads-mcp` instances from initiating connections to private IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) and cloud metadata addresses (e.g., `169.254.169.254`).
* Review application logs for `meta-ads-mcp` to identify attempts to call `upload_ad_image` with suspicious `image_url` parameters referencing internal network addresses or cloud metadata endpoints as shown in the IOCs section.
