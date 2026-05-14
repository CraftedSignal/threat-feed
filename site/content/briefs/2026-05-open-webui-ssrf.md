---
title: Open WebUI SSRF Vulnerability via URL Parsing Discrepancy (CVE-2026-45400)
slug: 2026-05-open-webui-ssrf
description: Open WebUI versions 0.9.4 and earlier are vulnerable to Server-Side Request Forgery (SSRF) due to a parsing difference between the urlparse and requests libraries in the `validate_url` function, allowing attackers to bypass URL validation and make requests to internal IP addresses.
date: "2026-05-14T20:37:19Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - ssrf
  - cve-2026-45400
  - open-webui
  - web-application
  - github-advisory
vendors:
  - pip
products:
  - open-webui (<= 0.9.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-8w7q-q5jp-jvgx
rules:
  - title: Detect Open WebUI SSRF Attempt via Malicious URL
    description: Detects CVE-2026-45400 exploitation — Attempts to exploit the Open WebUI SSRF vulnerability by detecting URLs with embedded IP addresses and @ symbols
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Requests to Private IP Addresses
    description: Detects requests originating from the server to RFC1918 private IP addresses
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions 0.9.4 and earlier contain a server-side request forgery (SSRF) vulnerability (CVE-2026-45400) in the `validate_url` function. The vulnerability arises from inconsistent URL parsing between the `urlparse` and `requests` libraries. Specifically, `urlparse` may interpret a URL like `http://127.0.0.1:6666\@1.1.1.1` as pointing to the public IP address `1.1.1.1`, while the `requests` library interprets it as the internal IP address `127.0.0.1:6666`. This discrepancy allows an attacker to bypass the intended URL validation and make unauthorized requests to internal resources. Successful exploitation can lead to information disclosure or further internal network compromise. The vulnerability was reported on May 14, 2026.

## Attack Chain

1. The attacker crafts a malicious URL with the format `http://127.0.0.1:6666\@public.ip.address`.
2. The user provides the crafted URL to Open WebUI, which uses the `validate_url` function to validate the URL.
3. The `validate_url` function uses `urllib.parse.urlparse` to parse the hostname of the URL.
4. `urllib.parse.urlparse` incorrectly identifies the hostname as `public.ip.address` due to the presence of the `@` symbol after the internal IP address.
5. The validation logic considers `public.ip.address` as a public IP and approves the URL.
6. The application then uses the `requests.get` function to make a request to the validated URL.
7. `requests.get` interprets the URL differently and sends the request to the internal IP address `127.0.0.1:6666`.
8. The attacker successfully makes a request to the internal IP address, achieving SSRF and potentially gaining access to sensitive information or internal services.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-45400) in Open WebUI can allow an attacker to bypass URL validation and make unauthorized requests to internal resources. This may lead to information disclosure, access to internal services, or further compromise of the internal network. The severity is rated as high due to the potential for significant impact on confidentiality and integrity. Affected organizations may experience data breaches or service disruptions.

## Recommendation

*   Upgrade to a patched version of Open WebUI that addresses the URL parsing discrepancy.
*   Deploy the Sigma rule `Detect Open WebUI SSRF Attempt via Malicious URL` to detect attempts to exploit this vulnerability.
*   Review and harden URL validation logic within the Open WebUI application to ensure consistent parsing across different libraries.
*   Implement network segmentation and access controls to limit the impact of potential SSRF vulnerabilities.
