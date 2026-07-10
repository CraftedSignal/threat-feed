---
title: WWBN AVideo Server-Side Request Forgery (SSRF) Vulnerability
slug: 2024-01-02-avideo-ssrf
description: WWBN AVideo versions prior to 26.0 are vulnerable to Server-Side Request Forgery (SSRF) via the `webSiteRootURL` parameter in `saveDVR.json.php`, allowing unauthenticated attackers to make arbitrary HTTP requests from the server.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - avideo
  - cve-2026-33351
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33351
rules:
  - title: Detect AVideo SSRF Attempt via webSiteRootURL
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in WWBN AVideo by monitoring requests to saveDVR.json.php with a suspicious webSiteRootURL parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo SSRF Attempt via file_get_contents in Request
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in WWBN AVideo by monitoring requests to saveDVR.json.php containing file_get_contents in the request.
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

A Server-Side Request Forgery (SSRF) vulnerability has been identified in WWBN AVideo, an open-source video platform. The vulnerability, tracked as CVE-2026-33351, affects versions prior to 26.0. Specifically, the issue resides within the `plugin/Live/standAloneFiles/saveDVR.json.php` script. The vulnerability occurs when the AVideo Live plugin is deployed in standalone mode, where the `$_REQUEST['webSiteRootURL']` parameter is directly used to construct a URL. The server then fetches this URL using `file_get_contents()` without proper authentication, origin validation, or URL allowlisting. Successful exploitation allows unauthenticated attackers to force the AVideo server to make arbitrary HTTP requests to internal or external resources, potentially leading to information disclosure, internal service compromise, or denial-of-service. Version 26.0 contains a patch for this vulnerability.

## Attack Chain

1.  The attacker identifies a vulnerable AVideo instance running a version prior to 26.0 with the Live plugin enabled in standalone mode.
2.  The attacker crafts a malicious HTTP request targeting the `saveDVR.json.php` endpoint.
3.  The malicious request includes the `webSiteRootURL` parameter, setting it to a URL controlled by the attacker (e.g., an internal service or an external server).
4.  The AVideo server receives the request and passes the attacker-controlled URL to the `file_get_contents()` function.
5.  The `file_get_contents()` function makes an HTTP request to the attacker-specified URL from the AVideo server.
6.  If the attacker specified an internal service, the AVideo server may inadvertently expose sensitive information or trigger unintended actions on the internal service.
7.  If the attacker specified an external server, the AVideo server sends an HTTP request to the attacker-controlled server.
8.  The attacker-controlled server receives the request, potentially revealing the AVideo server's IP address and allowing the attacker to perform further reconnaissance or launch attacks against other internal systems.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-33351) could allow an unauthenticated attacker to probe internal network resources, potentially leading to the discovery of sensitive information or the compromise of other internal services. An attacker could also use the AVideo server as a proxy to make requests to external services, masking their origin and potentially bypassing security controls. While the number of affected AVideo instances is unknown, organizations using versions prior to 26.0 are at risk. The impact can range from information disclosure to a full compromise of the AVideo server and potentially other internal resources.

## Recommendation

*   Upgrade WWBN AVideo to version 26.0 or later to patch the SSRF vulnerability (CVE-2026-33351).
*   Implement a web application firewall (WAF) rule to filter requests to `plugin/Live/standAloneFiles/saveDVR.json.php` that contain suspicious URLs in the `webSiteRootURL` parameter.
*   Deploy the Sigma rule provided below to detect attempts to exploit the SSRF vulnerability by monitoring HTTP requests to the vulnerable endpoint with suspicious `webSiteRootURL` parameters.
*   If upgrading is not immediately possible, consider disabling the Live plugin or restricting access to the `saveDVR.json.php` endpoint.
