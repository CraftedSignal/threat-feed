---
title: PraisonAI SSRF Vulnerability via URL Parsing Discrepancy
slug: 2026-05-praisonai-ssrf
description: PraisonAI versions 1.6.31 and earlier contain a Server-Side Request Forgery (SSRF) vulnerability due to inconsistent URL parsing between the application's validation logic and the underlying requests library, allowing attackers to bypass intended security checks and access internal resources.
date: "2026-05-06T22:08:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - praisonai
  - vulnerability
vendors:
  - pip
products:
  - praisonaiagents
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-q9pw-vmhh-384g
rules:
  - title: PraisonAI SSRF Attempt via URL Parsing Discrepancy
    description: Detects potential SSRF attacks against PraisonAI by identifying requests containing a URL with the format 'http://internal-ip@external-ip'.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: PraisonAI SSRF - Requests Library Bypass
    description: This rule detects requests that bypass URL validation by leveraging discrepancies between urlparse and requests libraries.
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

PraisonAI, a project utilizing URL validation to prevent SSRF attacks, is vulnerable due to a discrepancy in how URLs are parsed. Specifically, the application's `_validate_url` function relies on `urlparse` for security checks, while the actual HTTP requests are made using the `requests` library. The vulnerability arises from the differing interpretations of URLs containing both an IP address and a username/password component (e.g., `http://127.0.0.1:6666\@1.1.1.1`). The `urlparse` function extracts the hostname after the `@` symbol (1.1.1.1), while `requests` connects to the host before the `@` symbol (127.0.0.1).  This allows attackers to bypass the URL validation and send requests to internal resources. This affects PraisonAI agents version 1.6.31 and earlier and could allow access to internal services.

## Attack Chain

1. The attacker identifies a PraisonAI endpoint that accepts a URL as input.
2. The attacker crafts a malicious URL in the format `http://127.0.0.1:6666\@1.1.1.1`.
3. The application's `_validate_url` function parses the URL using `urlparse`, which resolves the host to `1.1.1.1` (a public IP).
4. The validation logic incorrectly identifies the target as an external resource, and allows the request to proceed.
5. The application then uses `requests.get` to make an HTTP request to the provided URL.
6. The `requests` library interprets the URL differently and connects to `127.0.0.1:6666` (a local resource).
7. The request is sent to the internal service running on `127.0.0.1:6666`.
8. The attacker gains access to the internal service, potentially leading to information disclosure or further exploitation.

## Impact

Successful exploitation of this SSRF vulnerability allows attackers to bypass intended security controls and access internal resources that are not meant to be exposed to the external network. This could lead to the disclosure of sensitive information, the execution of arbitrary code on internal systems, or further lateral movement within the network. The affected package, `pip/praisonaiagents`, is vulnerable in versions 1.6.31 and earlier.

## Recommendation

*   Deploy the Sigma rule `PraisonAI SSRF Attempt via URL Parsing Discrepancy` to detect attempts to exploit this vulnerability by monitoring for requests with the specific URL format.
*   Apply the patch or upgrade to a version of PraisonAI agents greater than 1.6.31 to remediate CVE-2026-44335.
*   Implement additional server-side validation to prevent SSRF as a defense-in-depth measure.
