---
title: BidingCC BuildingAI SSRF Vulnerability (CVE-2026-7065)
slug: 2024-01-buildingai-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in BidingCC BuildingAI up to version 26.0.1, allowing remote attackers to manipulate the `url` argument in the `uploadRemoteFile` function of `file-storage.service.ts` to conduct SSRF attacks.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-7065
  - web-application
vendors:
  - BidingCC
products:
  - BuildingAI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery (SSRF)
cves:
  - id: CVE-2026-7065
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7065
rules:
  - title: Detect BuildingAI SSRF Attempt via URL Parameter
    description: Detects attempts to exploit the SSRF vulnerability in BuildingAI by monitoring requests to the uploadRemoteFile endpoint with suspicious URL parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
  - title: Detect BuildingAI SSRF Attempt via POST Request
    description: Detects attempts to exploit the SSRF vulnerability in BuildingAI by monitoring POST requests to the uploadRemoteFile endpoint with suspicious URL parameters in the request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
rules_count: 2
---

BidingCC BuildingAI, up to version 26.0.1, is vulnerable to a server-side request forgery (SSRF) attack. The vulnerability resides within the `uploadRemoteFile` function located in `packages/core/src/modules/upload/services/file-storage.service.ts`. An attacker can remotely manipulate the `url` argument passed to this function to force the server to make requests to arbitrary internal or external resources. This vulnerability has been publicly disclosed and is considered exploitable. The vendor was notified of the issue, but has not responded. Successful exploitation can lead to information disclosure, internal service compromise, or other malicious activities.

## Attack Chain

1.  Attacker identifies a BidingCC BuildingAI instance running a vulnerable version (<= 26.0.1).
2.  Attacker crafts a malicious URL containing the address of an internal resource or external server.
3.  Attacker calls the `uploadRemoteFile` API endpoint, providing the crafted URL as the `url` argument.
4.  The `uploadRemoteFile` function, without proper validation, uses the provided URL to initiate a request.
5.  The BuildingAI server makes an HTTP request to the attacker-specified URL.
6.  If the URL points to an internal resource, the server retrieves sensitive data from that resource.
7.  If the URL points to an external server controlled by the attacker, the server may leak internal information (e.g., internal IP addresses) or be used for further attacks.
8.  The attacker receives the response from the manipulated request, achieving information disclosure or a foothold for further exploitation.

## Impact

Successful exploitation of the SSRF vulnerability (CVE-2026-7065) in BidingCC BuildingAI can lead to the exposure of sensitive internal information, such as configuration files, internal service endpoints, and potentially database credentials. This information can be leveraged to further compromise the BuildingAI instance or other internal systems. The impact is significant due to the potential for lateral movement and privilege escalation within the affected organization's infrastructure. The lack of vendor response exacerbates the risk.

## Recommendation

*   Deploy the Sigma rule provided below to detect exploitation attempts against the `uploadRemoteFile` endpoint (Log source: webserver).
*   Implement strict input validation and sanitization on the `url` parameter of the `uploadRemoteFile` function to prevent arbitrary URL requests (CVE-2026-7065).
*   Consider restricting outbound network access from the BuildingAI server to only necessary resources to limit the impact of successful SSRF attacks.
*   Monitor web server logs for unusual requests originating from the BuildingAI server to detect potential SSRF activity.
