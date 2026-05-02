---
title: PixelYourSite Pro WordPress Plugin SSRF Vulnerability (CVE-2026-7049)
slug: 2026-05-pys-ssrf
description: The PixelYourSite Pro WordPress plugin is vulnerable to server-side request forgery (SSRF), allowing unauthenticated attackers to make arbitrary web requests from the server, potentially querying or modifying internal services.
date: "2026-05-02T06:16:04Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - ssrf
  - wordpress
  - plugin
vendors:
  - WordPress
products:
  - PixelYourSite Pro – Your smart PIXEL (TAG) Manager plugin for WordPress <= 12.5.0.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7049
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7049
rules:
  - title: Detect Suspicious PixelYourSite Pro SSRF Attempts
    description: Detects attempts to exploit the SSRF vulnerability (CVE-2026-7049) in the PixelYourSite Pro WordPress plugin by monitoring requests to the scan_video parameter with potentially malicious URLs.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect PixelYourSite Pro SSRF Attempts to Internal Metadata
    description: Detects attempts to exploit the SSRF vulnerability (CVE-2026-7049) in the PixelYourSite Pro WordPress plugin by monitoring requests to the scan_video parameter targeting cloud metadata endpoints.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-7049 is a server-side request forgery (SSRF) vulnerability found in the PixelYourSite Pro WordPress plugin. Specifically, all versions up to and including 12.5.0.1 are affected. This vulnerability allows unauthenticated attackers to send requests to arbitrary internal or external resources, as viewed from the web server. Although the fetched response bodies are not directly returned to the attacker (making it a blind SSRF), the application parses these responses internally, creating opportunities for reconnaissance and potentially for exploiting vulnerable internal services. Successful exploitation could expose sensitive information or allow unauthorized modification of internal systems.

## Attack Chain

1. An unauthenticated attacker identifies the `scan_video` parameter as an SSRF entry point.
2. The attacker crafts a malicious HTTP request targeting the WordPress server with the vulnerable PixelYourSite Pro plugin. The request includes the `scan_video` parameter set to a URL pointing to an internal resource (e.g., internal IP address or hostname).
3. The WordPress server receives the malicious request.
4. The PixelYourSite Pro plugin processes the request and initiates an HTTP request to the URL specified in the `scan_video` parameter.
5. The WordPress server makes a request to the internal resource.
6. The response from the internal resource is received by the WordPress server.
7. The PixelYourSite Pro plugin parses the response body, potentially revealing information about the internal service.
8. Depending on the targeted internal service and the attacker's crafted request, the attacker might be able to modify information or execute commands on the internal service, even though the response is not directly returned to the attacker.

## Impact

Successful exploitation of CVE-2026-7049 allows an unauthenticated attacker to perform reconnaissance of internal network resources. The blind nature of the SSRF limits the attacker's immediate visibility into the response, but internal parsing of the response allows for potential information disclosure and exploitation of vulnerable internal services. The scope of the impact depends heavily on the configuration of the internal network and the services exposed.

## Recommendation

*   Upgrade the PixelYourSite Pro plugin to a version greater than 12.5.0.1 to patch CVE-2026-7049.
*   Deploy the Sigma rule `Detect Suspicious PixelYourSite Pro SSRF Attempts` to monitor for exploitation attempts targeting the `scan_video` parameter.
*   Review and restrict internal network access to sensitive services to mitigate the potential impact of SSRF vulnerabilities.
