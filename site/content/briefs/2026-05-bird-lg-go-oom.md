---
title: Bird-lg-go Unbounded JSON Decode Denial of Service (CVE-2026-45047)
slug: 2026-05-bird-lg-go-oom
description: Bird-lg-go is vulnerable to a denial-of-service (DoS) attack (CVE-2026-45047) where an unauthenticated remote attacker can cause an out-of-memory error by streaming an extremely large JSON payload to the apiHandler, leading to termination of the bird-lg-go daemon.
date: "2026-05-11T16:19:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - json
  - CVE-2026-45047
  - linux
products:
  - bird-lg-go
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-39qr-rc93-vhqm
  - CVE-2026-45047
rules:
  - title: Detect Bird-lg-go Excessive JSON Payload
    description: Detects abnormally large HTTP POST requests to apiHandler or webHandlerTelegramBot, indicating a potential denial-of-service attempt (CVE-2026-45047).
    platform: sigma
    severity: medium
    tactics:
      - dos
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect Bird-lg-go Out-of-Memory Errors
    description: 'Detects ''fatal error: runtime: out of memory'' messages in bird-lg-go logs, potentially indicating a denial-of-service (CVE-2026-45047).'
    platform: sigma
    severity: high
    tactics:
      - dos
    techniques:
      - T1499.001
    data_sources:
      - application
      - linux
rules_count: 2
---

Bird-lg-go is susceptible to a denial-of-service vulnerability due to unbounded JSON decoding in the `apiHandler` function. Specifically, the application uses `json.NewDecoder(r.Body).Decode(&request)` without implementing a maximum read size limit. This allows an unauthenticated remote attacker to send an arbitrarily large JSON payload to the application. The Go JSON decoder attempts to allocate memory for the entire parsed structure, and an attacker can exploit this by sending gigabytes of padded data, rapidly exhausting the available memory. This triggers a `fatal error: runtime: out of memory` condition, causing the Linux OOM Killer to terminate the `bird-lg-go` daemon, effectively creating a remote denial of service (RDoS). This affects bird-lg-go versions prior to commit 0ff87024cb9e.

## Attack Chain

1. An unauthenticated attacker establishes a TCP connection to the bird-lg-go server.
2. The attacker sends an HTTP POST request to an endpoint handled by the `apiHandler` or `webHandlerTelegramBot`.
3. The HTTP request body contains a malicious JSON payload.
4. The attacker streams an extremely large, potentially endless, JSON payload without any size restrictions.
5. The `json.NewDecoder(r.Body).Decode(&request)` function attempts to decode the JSON.
6. The Go JSON decoder allocates memory to store the decoded JSON structure.
7. The attacker's oversized payload exhausts the available memory.
8. The `bird-lg-go` process encounters a `fatal error: runtime: out of memory` condition and terminates due to the Linux OOM Killer.

## Impact

The vulnerability can cause a complete denial of service by crashing the `bird-lg-go` daemon. A single attacker can disrupt the service by exhausting the server's memory resources. The impact is significant as it affects the availability of the application. While the exact number of victims is not specified, any deployment of a vulnerable version of `bird-lg-go` is susceptible to this attack. Successful exploitation leads to service interruption until the daemon is manually restarted.

## Recommendation

*   Apply the patch or upgrade to a version of `bird-lg-go` containing the fix for CVE-2026-45047 to mitigate the unbounded JSON decoding vulnerability.
*   Implement resource limits, such as `http.MaxBytesReader`, to restrict the size of incoming HTTP request bodies to prevent excessive memory allocation, mitigating CVE-2026-45047.
*   Deploy the Sigma rule "Detect Bird-lg-go Excessive JSON Payload" to identify potentially malicious requests based on the size of the request body.
