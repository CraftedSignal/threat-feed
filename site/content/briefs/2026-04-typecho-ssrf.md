---
title: Typecho <= 1.3.0 Server-Side Request Forgery Vulnerability (CVE-2026-7025)
slug: 2026-04-typecho-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in Typecho up to version 1.3.0, allowing remote attackers to manipulate the X-Pingback/link argument in the Service::sendPingHandle function to potentially make arbitrary HTTP requests.
date: "2026-04-26T08:17:46Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - ssrf
  - cve-2026-7025
  - typecho
vendors:
  - Typecho
products:
  - Typecho (<= 1.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7025
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7025
  - https://vuldb.com/submit/797772
  - https://vuldb.com/vuln/359605
  - https://vuldb.com/vuln/359605/cti
  - https://wang1rrr.github.io/2026/03/04/CVE-Report-Typecho-v1-3-0-SSRF/
rules:
  - title: Detect Suspicious X-Pingback Header
    description: Detects suspicious outbound connections initiated by a web server due to a manipulated X-Pingback header, indicating a potential SSRF vulnerability exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Typecho SSRF - External URL in X-Pingback Header
    description: Detects potential SSRF attempts in Typecho by monitoring for X-Pingback headers containing URLs pointing to external domains.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Typecho is vulnerable to a server-side request forgery (SSRF) vulnerability (CVE-2026-7025) affecting versions up to 1.3.0. The vulnerability resides in the `Service::sendPingHandle` function within the `var/Widget/Service.php` file, specifically impacting the Ping Back Service Endpoint component. An attacker can remotely trigger this vulnerability by manipulating the `X-Pingback/link` argument. Publicly available exploits exist, increasing the risk of exploitation. The vendor was notified but did not respond. This vulnerability allows an attacker to potentially make arbitrary HTTP requests from the server, leading to information disclosure or further compromise.

## Attack Chain

1.  The attacker identifies a Typecho instance running a vulnerable version (<= 1.3.0).
2.  The attacker crafts a malicious HTTP request targeting the Pingback service endpoint.
3.  The malicious request includes a manipulated `X-Pingback` or `link` argument pointing to an attacker-controlled server or internal resource.
4.  The `Service::sendPingHandle` function processes the request and attempts to fetch the resource specified in the `X-Pingback/link` argument.
5.  Due to the SSRF vulnerability, the Typecho server makes an outbound HTTP request to the attacker-specified URL.
6.  The attacker's server logs the incoming request from the Typecho server, confirming the SSRF vulnerability.
7.  The attacker could potentially use this SSRF vulnerability to scan internal networks, read sensitive files, or interact with internal services.
8.  Successful exploitation could lead to information disclosure, further exploitation of internal services, or denial-of-service attacks.

## Impact

Successful exploitation of CVE-2026-7025 can allow an attacker to perform unauthorized actions on the internal network of the Typecho server. This includes port scanning, accessing internal services, and potentially reading sensitive data. The number of affected installations is unknown, but any Typecho instance running version 1.3.0 or earlier is vulnerable. The impact is limited to the permissions of the Typecho web server process, but can expose sensitive internal services that are not directly accessible from the internet.

## Recommendation

*   Apply input validation and sanitization to the `X-Pingback/link` argument to prevent arbitrary URL inclusion, mitigating CVE-2026-7025.
*   Monitor web server logs for suspicious requests containing unusual URLs in the `X-Pingback` header, which can indicate SSRF attempts.
*   Implement network segmentation to limit the impact of potential SSRF attacks by restricting the web server's access to internal resources.
*   Deploy the Sigma rule `Detect Suspicious X-Pingback Header` to identify potential SSRF attempts targeting the Pingback service.
*   Audit outbound network connections from the web server to detect unauthorized access to internal resources as a result of SSRF.
