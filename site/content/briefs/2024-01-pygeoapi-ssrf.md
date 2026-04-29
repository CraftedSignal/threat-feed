---
title: pygeoapi Unauthenticated SSRF Vulnerability in OGC API - Processes Subscriber
slug: 2024-01-pygeoapi-ssrf
description: pygeoapi versions 0.23.0 to 0.23.2 contain an unauthenticated server-side request forgery (SSRF) vulnerability where OGC API process execution requests can use the subscriber object to make requests to internal HTTP services, which is resolved in version 0.23.3 by disabling internal requests by default.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - pygeoapi
  - ssrf
  - ogc api
  - cve-2026-42352
  - vulnerability
  - cloud
products:
  - pygeoapi (0.23.0 - 0.23.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery (SSRF)
references:
  - https://github.com/advisories/GHSA-jgvc-94c8-3chc
  - https://github.com/geopython/pygeoapi/commit/3a63f5b0cc6275e3ae0edb47726b13a43cdd90ef
rules:
  - title: Detect pygeoapi SSRF Attempt via Subscriber Object
    description: Detects potential SSRF attempts in pygeoapi by monitoring for suspicious requests containing subscriber objects targeting internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1199
    data_sources:
      - webserver
      - linux
  - title: Detect pygeoapi SSRF Attempt via OGC API Processes
    description: Detects potential SSRF attempts in pygeoapi by monitoring for suspicious requests to OGC API Processes endpoint with internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1199
    data_sources:
      - webserver
      - linux
rules_count: 2
---

pygeoapi versions 0.23.0, 0.23.1, and 0.23.2 are vulnerable to Server-Side Request Forgery (SSRF). The vulnerability stems from the OGC API - Processes functionality, specifically how it handles the `subscriber` object during process execution. An unauthenticated attacker can exploit this flaw to send requests to internal HTTP services, potentially gaining access to sensitive information or triggering unintended actions within the internal network. This issue was patched in version 0.23.3 by disabling internal HTTP requests by default, unless explicitly allowed in the configuration. The patch includes the introduction of an `allow_internal_requests` directive for administrators who require this functionality. This vulnerability poses a significant risk to organizations using affected versions of pygeoapi.

## Attack Chain

1.  An unauthenticated attacker identifies a pygeoapi instance running a vulnerable version (0.23.0 - 0.23.2).
2.  The attacker crafts a malicious OGC API process execution request.
3.  Within the request, the attacker manipulates the `subscriber` object.
4.  The `subscriber` object is configured to target an internal HTTP service by specifying the internal service's address.
5.  pygeoapi processes the request without proper validation of the `subscriber` object's target.
6.  pygeoapi initiates an HTTP request to the attacker-specified internal service.
7.  The internal service responds to pygeoapi.
8.  pygeoapi may then relay information received from the internal service back to the attacker, or the attacker might be able to trigger actions based on the SSRF.

## Impact

Successful exploitation of this SSRF vulnerability allows an unauthenticated attacker to interact with internal HTTP services that should not be publicly accessible. This can lead to the disclosure of sensitive information, such as internal configurations, API keys, or customer data. The attacker may also be able to trigger actions on the internal services, potentially leading to service disruption or data manipulation. The severity of the impact depends on the nature and security posture of the internal services exposed by this vulnerability.

## Recommendation

*   Upgrade to pygeoapi version 0.23.3 or later to remediate CVE-2026-42352.
*   Apply the provided patch [3a63f5b0cc6275e3ae0edb47726b13a43cdd90ef](https://github.com/geopython/pygeoapi/commit/3a63f5b0cc6275e3ae0edb47726b13a43cdd90ef) if upgrading is not immediately feasible.
*   If upgrading or patching is not immediately feasible, disable process-based resources in the pygeoapi configuration as a workaround.
