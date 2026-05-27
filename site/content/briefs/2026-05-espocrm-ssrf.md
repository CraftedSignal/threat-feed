---
title: EspoCRM 9.3.3 SSRF Vulnerability (CVE-2026-33534)
slug: 2026-05-espocrm-ssrf
description: A public exploit is available for EspoCRM 9.3.3, exploiting a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-33534) allowing authenticated attackers to potentially access internal resources.
date: "2026-05-27T13:11:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:espocrm:espocrm:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - webapps
  - cve-2026-33534
vendors:
  - EspoCRM
products:
  - EspoCRM 9.3.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33534
    cvss: 4.3
    epss: 0.00249
references:
  - https://www.exploit-db.com/exploits/52583
  - https://github.com/espocrm/espocrm/security/advisories/GHSA-h7gx-8gwv-7g73
  - CVE-2026-33534
rules:
  - title: Detect EspoCRM SSRF via Encoded Loopback
    description: Detects CVE-2026-33534 exploitation — SSRF attempts in EspoCRM by detecting encoded loopback addresses in requests to the fromImageUrl endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect EspoCRM SSRF via Alternative IPv4 Notation - POST Body
    description: Detects CVE-2026-33534 exploitation — SSRF attempts in EspoCRM by detecting encoded loopback addresses in requests to the fromImageUrl endpoint (POST body).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A Server-Side Request Forgery (SSRF) vulnerability has been identified in EspoCRM version 9.3.3, tracked as CVE-2026-33534. An authenticated attacker can exploit this vulnerability to potentially force the server to make requests to unintended locations, including internal services that are normally protected. The public availability of an exploit (EDB-52583) increases the risk of exploitation. The vulnerability exists in the `Attachment/fromImageUrl` endpoint which is used to fetch images from a provided URL. Attackers can manipulate the `url` parameter to point to internal resources by bypassing URL validation through techniques like IP address encoding.

## Attack Chain

1.  Attacker authenticates to the EspoCRM application.
2.  Attacker crafts a malicious request to the `/api/v1/Attachment/fromImageUrl` endpoint.
3.  The request includes a `url` parameter containing a manipulated IP address (e.g., octal, hex, or decimal representation) pointing to an internal resource.
4.  EspoCRM server, due to insufficient validation, processes the crafted URL.
5.  The server initiates a request to the attacker-specified internal resource.
6.  The server receives a response from the internal resource.
7.  The server may then process or display the received data, potentially leaking sensitive information or enabling further attacks.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-33534) in EspoCRM 9.3.3 could allow an attacker to access sensitive internal resources, such as internal web applications, databases, or configuration files. This can lead to information disclosure, privilege escalation, or further compromise of the EspoCRM system and the underlying network. The exploit's public availability means organizations using unpatched versions of EspoCRM are at heightened risk.

## Recommendation

*   Apply the patch or upgrade to a version of EspoCRM that addresses CVE-2026-33534 as outlined in the vendor's advisory ([https://github.com/espocrm/espocrm/security/advisories/GHSA-h7gx-8gwv-7g73](https://github.com/espocrm/espocrm/security/advisories/GHSA-h7gx-8gwv-7g73)).
*   Implement input validation and sanitization on the `url` parameter of the `/api/v1/Attachment/fromImageUrl` endpoint to prevent SSRF attacks.
*   Deploy the Sigma rule `Detect EspoCRM SSRF via Encoded Loopback` to identify exploitation attempts targeting CVE-2026-33534.
*   Monitor web server logs for requests to the `/api/v1/Attachment/fromImageUrl` endpoint containing unusual or encoded IP addresses in the `url` parameter.
