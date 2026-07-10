---
title: Scriban Template Engine Remote Denial-of-Service via Uncontrolled Memory Allocation
slug: 2024-01-scriban-dos
description: The Scriban template engine is vulnerable to a denial-of-service attack due to missing validation in the `string.pad_left` and `string.pad_right` functions, allowing unauthenticated attackers to trigger excessive memory allocation and crash the service by sending a crafted HTTP request to a vulnerable endpoint that processes untrusted Scriban templates.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - scriban
  - dos
  - denial-of-service
  - template-injection
vendors:
  - Scriban
products:
  - Scriban
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-v66j-x4hw-fv9g
rules:
  - title: Detect Scriban PadLeft/PadRight DoS Attempt
    description: Detects attempts to exploit the Scriban `pad_left` or `pad_right` denial-of-service vulnerability by identifying HTTP requests with large width parameters.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 1
---

Scriban is a .NET template engine similar to Liquid. Versions prior to 7.0.0 are vulnerable to a denial-of-service attack. The `string.pad_left` and `string.pad_right` template functions in Scriban lack validation on the `width` parameter. This allows an attacker to control the size of a string allocation, leading to a potential `OutOfMemoryException`. The vulnerability is triggered when Scriban is used to render untrusted template input. A publicly accessible Scriban playground, `Scriban.AppService`, deployed on Azure is vulnerable, allowing an unauthenticated attacker to crash the service by sending a specially crafted HTTP request. A 39-byte payload is sufficient to trigger a ~1GB memory allocation, crashing the service. Rate limiting is present at 30 requests/minute but is insufficient to mitigate the attack as each request still triggers a large memory allocation.

## Attack Chain

1.  An attacker crafts a malicious Scriban template containing either the `string.pad_left` or `string.pad_right` function with a large `width` value (e.g., 500000000).
2.  The attacker sends an HTTP POST request to the `/api/render` endpoint of a vulnerable Scriban application such as `Scriban.AppService`.
3.  The POST request body contains a JSON payload with the "template" field set to the malicious Scriban template.
4.  The vulnerable application receives the request and extracts the template from the JSON payload.
5.  The application calls the `template.Render()` function to process the Scriban template.
6.  During template rendering, the `string.pad_left` or `string.pad_right` function is called with the attacker-controlled `width` value.
7.  The application attempts to allocate a string of the specified `width` in memory. Due to the large `width` value, this allocation can be on the order of gigabytes.
8.  If the allocation exceeds available memory, the .NET runtime throws an `OutOfMemoryException`, crashing the application process and causing a denial of service.

## Impact

This vulnerability allows an unauthenticated attacker to remotely crash any application that renders untrusted Scriban templates. In the specific case of the official Scriban playground (`scriban-a7bhepbxcrbkctgf.canadacentral-01.azurewebsites.net`), a single HTTP request can trigger an `OutOfMemoryException` and crash the service. Sustained requests at the rate limit (30/min) can create continuous memory pressure (~30GB/min), preventing the service from recovering. Successful exploitation leads to a denial of service, rendering the application unavailable to legitimate users.

## Recommendation

*   Apply the vendor-supplied patch to upgrade Scriban to version 7.0.0 or later, which includes validation on the `width` parameter for `StringFunctions.PadLeft` and `StringFunctions.PadRight` to prevent excessive memory allocation.
*   For web applications using Scriban, implement input validation on the template data received from users to prevent injection of arbitrary `pad_left` and `pad_right` calls.
*   Monitor web server logs (category: `webserver`, product: `linux`) for suspicious POST requests to the `/api/render` endpoint with unusually large values in the `template` parameter, as indicated by the rule "Detect Scriban PadLeft/PadRight DoS Attempt".
*   Deploy the Sigma rule "Detect Scriban PadLeft/PadRight DoS Attempt" to identify attempts to exploit this vulnerability in real-time.
*   Consider implementing resource limits (e.g., memory limits) on the Scriban rendering process to prevent a single malicious request from consuming excessive resources.
