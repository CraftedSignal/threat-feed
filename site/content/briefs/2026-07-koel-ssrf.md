---
title: Koel Authenticated Full-Read SSRF via Subsonic Internet Radio Stations
slug: 2026-07-koel-ssrf
description: An authenticated user can exploit a Server-Side Request Forgery (SSRF) vulnerability, CVE-2026-54493, in Koel v9.6.0 via the Subsonic-compatible radio endpoints, which lack proper URL validation, allowing the server to fetch and return the body of internal network resources.
date: "2026-07-15T17:15:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - web-application
  - vulnerability
  - koel
  - subsonic
vendors:
  - phanan
products:
  - Koel (<= 9.6.0)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: 'Practical impact includes: Reading loopback-only, RFC1918, or Docker-bridge HTTP services; Accessing internal admin panels, metrics services, or metadata endpoints that are not publicly exposed; Performing internal HTTP reconnaissance'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The response body is returned to the attacker... That makes this a full-read SSRF... The attacker is not only limited to causing an internal request, but also they can read the HTTP response... retrieving content through Koel itself
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6p96-cfg5-4vhp
rules:
  - title: Detect CVE-2026-54493 Exploitation - Koel Subsonic SSRF Attempt
    description: Detects CVE-2026-54493 exploitation - attempts to create or update Koel radio stations via Subsonic endpoints with internal IP addresses or hostnames in the streamUrl parameter, indicating an SSRF attempt.
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1592
    data_sources:
      - webserver
rules_count: 1
---

A critical Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2026-54493, has been discovered in Koel versions up to and including v9.6.0. This flaw affects the Subsonic-compatible radio endpoints, specifically `createInternetRadioStation.view` and `updateInternetRadioStation.view`, which do not enforce the same URL validation as the regular web API. An authenticated attacker can exploit this by crafting a request to these endpoints, supplying a malicious `streamUrl` parameter pointing to an internal or private network resource. When the created or updated radio station is subsequently played, the Koel server initiates a server-side request to the attacker-controlled URL. Unlike blind SSRF, this vulnerability allows the attacker to receive the full response body from the internal resource, facilitating internal HTTP reconnaissance, access to sensitive internal HTTP services, and potential data exfiltration from the server's network. The issue was validated against `phanan/koel:9.6.0` image.

## Attack Chain

1. An authenticated attacker obtains valid API and Subsonic API keys for the target Koel instance.
2. The attacker crafts an HTTP GET or POST request to Koel's Subsonic endpoint, such as `/rest/createInternetRadioStation.view`.
3. The request includes a `streamUrl` parameter pointing to a target internal or private network resource (e.g., `http://172.17.0.1:18090/feed.xml`).
4. Koel's Subsonic endpoint processes the request without applying URL validation checks, storing the malicious `streamUrl` as a radio station property.
5. The attacker resolves the unique identifier (ID) of the newly created or updated radio station.
6. The attacker sends an HTTP GET request to the stream endpoint, `/radio/stream/{id}`, attempting to play the crafted radio station.
7. Koel's `RadioStreamProxy::openStream()` function initiates a server-side request to the `streamUrl` value stored in the radio station object.
8. The full HTTP response body from the internal network resource is returned to the Koel server, which then forwards it to the attacker's client, enabling full-read SSRF.

## Impact

The successful exploitation of CVE-2026-54493 allows an authenticated attacker to perform extensive internal network reconnaissance and potentially exfiltrate sensitive data. Attackers can read loopback-only, RFC1918, or Docker-bridge HTTP services, access internal admin panels, metrics services, or metadata endpoints that are not publicly exposed. This full-read Server-Side Request Forgery significantly amplifies the risk compared to blind SSRF, as it grants attackers direct access to the content of internal HTTP responses, thereby exposing sensitive configurations, credentials, or internal application data. The scope of targeted entities includes any internal HTTP service reachable from the Koel server.

## Recommendation

* Patch CVE-2026-54493 immediately by upgrading Koel to a version where the Subsonic request validators apply the `SafeUrl` and `HasAudioContentType` rules to the `streamUrl` parameter, as shown in the provided patch for `app/Http/Requests/Subsonic/CreateInternetRadioStationRequest.php` and `app/Http/Requests/Subsonic/UpdateInternetRadioStationRequest.php`.
* Implement defense-in-depth by ensuring the `RadioStreamProxy::openStream()` function performs a safety check on the URL before opening a stream, as suggested in the patch for `app/Services/Radio/RadioStreamProxy.php`.
* Deploy the Sigma rule "Detect CVE-2026-54493 Exploitation - Koel Subsonic SSRF Attempt" to your SIEM to identify attempts to create or update radio stations with internal IP addresses or hostnames.
* Ensure web server logs (e.g., Apache, Nginx access logs) are being collected for the `webserver` logsource category, as they are crucial for detecting the HTTP request patterns targeted by the detection rule.
