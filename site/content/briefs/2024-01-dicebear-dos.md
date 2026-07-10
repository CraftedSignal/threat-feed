---
title: DiceBear SVG Size Capping Bypass Leads to Denial of Service
slug: 2024-01-dicebear-dos
description: A denial-of-service vulnerability exists in DiceBear versions prior to 9.4.2 due to a bypassable regex in the `ensureSize()` function, allowing attackers to craft SVGs that cause out-of-memory crashes during rendering on Node.js.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - svg
  - vulnerability
vendors:
  - DiceBear
products:
  - DiceBear
  - '@dicebear/converter'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33418
rules:
  - title: DiceBear SVG Size Capping Bypass Attempt
    description: Detects attempts to bypass the DiceBear SVG size capping mechanism by identifying SVG files with extremely large width or height attributes.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Node.js Out-of-Memory Crash Related to DiceBear
    description: Detects Node.js processes crashing with out-of-memory errors, potentially related to the DiceBear SVG rendering vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

DiceBear is an avatar library used by designers and developers. Prior to version 9.4.2, a vulnerability exists in the `@dicebear/converter` package related to how SVG `width` and `height` attributes are handled. The `ensureSize()` function, intended to cap SVG dimensions at 2048px to prevent denial-of-service attacks, employed a regex-based approach. This approach could be circumvented by crafting malicious SVG input that tricks the regex into matching a non-functional `<svg` tag before the actual root element. The subsequent rendering process, which leverages `@resvg/resvg-js` on Node.js, then renders the SVG at the attacker-specified dimensions, potentially consuming excessive memory and leading to out-of-memory crashes, effectively causing a denial of service. Version 9.4.2 addresses this vulnerability by replacing the regex-based approach with XML-aware processing and adding a `fitTo` constraint as defense-in-depth.

## Attack Chain

1. An attacker crafts a malicious SVG file with oversized dimensions, designed to exploit the regex bypass. The SVG contains a decoy `<svg` tag before the real root element.
2. The attacker delivers the malicious SVG file to a system utilizing a vulnerable version of DiceBear (prior to 9.4.2). This could be through a file upload mechanism, API endpoint, or other data ingestion method.
3. The vulnerable `ensureSize()` function in `@dicebear/converter` processes the SVG file. The regex incorrectly identifies the decoy `<svg` tag and fails to properly cap the dimensions.
4. The oversized SVG is passed to `@resvg/resvg-js` for rendering.
5. `@resvg/resvg-js` attempts to render the SVG at the attacker-specified, oversized dimensions.
6. The rendering process consumes excessive memory, potentially exhausting available resources.
7. The Node.js process running the DiceBear library crashes due to an out-of-memory error.
8. The application relying on DiceBear becomes unavailable, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability can lead to a denial of service (DoS) condition, rendering applications that rely on the DiceBear library unavailable. The impact is particularly relevant for services that process user-supplied SVG avatars or images, as malicious users could trigger the vulnerability remotely. While the precise number of affected systems is unknown, any application using DiceBear prior to version 9.4.2 is potentially vulnerable. The CVSS v3.1 score is 7.5, indicating a high potential for disruption.

## Recommendation

*   Upgrade DiceBear to version 9.4.2 or later to incorporate the fix for CVE-2026-33418.
*   Monitor web server logs for unusual patterns in SVG file uploads or processing, looking for requests with extremely large specified dimensions.
*   Implement resource limits on processes that handle SVG rendering to mitigate the impact of potential memory exhaustion attacks.
