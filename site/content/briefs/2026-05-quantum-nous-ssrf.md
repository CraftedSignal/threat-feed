---
title: QuantumNous new-api SSRF Bypass via 0.0.0.0
slug: 2026-05-quantum-nous-ssrf
description: The QuantumNous new-api is vulnerable to SSRF attacks. The SSRF protection implemented in versions v0.9.0.5 (CVE-2025-59146) and v0.9.6 (CVE-2025-62155) can be bypassed by using the address `0.0.0.0`. An attacker with a valid API token can send a request to `/v1/chat/completions`, `/v1/responses`, or `/v1/messages` with `0.0.0.0` as the image/file URL host, which bypasses the private-IP filter and allows the server to issue HTTP requests to localhost, enabling a blind SSRF and possibly a full-read SSRF in specific configurations.
date: "2026-05-07T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - quantumnous
vendors:
  - QuantumNous
products:
  - new-api (<= 0.11.9-alpha.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-59146
    cvss: 8.5
    epss: 0.00043
  - id: CVE-2025-62155
    cvss: 8.5
    epss: 0.00043
references:
  - https://github.com/advisories/GHSA-v5c3-6wvc-pc2q
iocs:
  - type: url
    value: http://0.0.0.0:8080/probe.png
  - type: url
    value: https://dummyimage.com/600x180/111/fff.png&text=READBACK-OK-314159
ioc_counts:
  url: 2
rules:
  - title: Detect QuantumNous new-api SSRF Attempt via 0.0.0.0
    description: Detects network connections to 0.0.0.0 which can indicate an SSRF attempt in QuantumNous new-api.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect SSRF via Image URL with 0.0.0.0
    description: Detects SSRF attempts by monitoring web server logs for requests containing 'image_url' with a URL pointing to 0.0.0.0 in QuantumNous new-api.
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

The QuantumNous new-api is vulnerable to a Server-Side Request Forgery (SSRF) vulnerability due to an incomplete fix for previous SSRF issues (CVE-2025-59146, CVE-2025-62155). The vulnerability exists in versions up to 0.11.9-alpha.1. The SSRF protection implemented in v0.9.0.5 and hardened in v0.9.6 fails to block the address `0.0.0.0`, which resolves to localhost on Linux systems. An authenticated, regular user with any valid API token can exploit this by sending a request to specific endpoints such as `/v1/chat/completions` including `0.0.0.0` in the URL of an image or file. If the request is routed through an AWS/Bedrock Claude adaptor, this can be upgraded to a full-read SSRF where the fetched content is inlined into the model response, allowing for exfiltration of internal content.

## Attack Chain

1. An attacker obtains a valid API token for a regular user account on the QuantumNous new-api.
2. The attacker crafts a POST request to `/v1/chat/completions` with a JSON payload that includes a malicious `image_url` with the host set to `0.0.0.0` and a port in the allowed list (80, 443, 8080, 8443). For example: `"url": "http://0.0.0.0:8080/probe.png"`. The `stream: true` parameter is also set to trigger the fetch path.
3. The server-side code at `dto/openai_request.go` recognizes the `http(s)://` URL as a valid source and proceeds to collect metadata.
4. The `LoadFileSource()` function at `service/token_counter.go` determines that the file needs to be fetched based on the `shouldFetchFiles` setting.
5. The `loadFromURL()` function within `service/file_service.go` calls `DoDownloadRequest()`.
6. The `ValidateURLWithFetchSetting()` function at `service/download.go` incorrectly validates the URL, as `0.0.0.0` is not blocked by the IP filter.
7. The server initiates a TCP connection to `0.0.0.0` on the specified port.
8. If the request is routed through an AWS/Bedrock Claude channel, the fetched content from `0.0.0.0` is then inlined into the model request and leaked through the model's response (full-read SSRF). Otherwise, an attacker can probe internal services.

## Impact

An attacker with a valid user API token can exploit this SSRF vulnerability to probe internal services and potentially exfiltrate sensitive information. By bypassing the intended SSRF protections, the attacker can access resources on the localhost that should not be exposed. If the request is processed by a multimodal model like Claude via AWS/Bedrock, the fetched content can be directly leaked through the model's output, leading to full-read SSRF. The vulnerability can be exploited by any registered user since user registration is often enabled by default.

## Recommendation

*   Apply a patch that adds `0.0.0.0/8` to the deny list in `isPrivateIP()` as suggested in the advisory.
*   Deploy the Sigma rule "Detect QuantumNous new-api SSRF Attempt via 0.0.0.0" to detect attempts to exploit this vulnerability by monitoring network connections to 0.0.0.0.
*   Block the URLs `http://0.0.0.0:8080/probe.png` and `https://dummyimage.com/600x180/111/fff.png&text=READBACK-OK-314159` at the network perimeter to prevent exploitation.
*   Upgrade to a version of the QuantumNous new-api that includes a fix for CVE-2026-42339.
