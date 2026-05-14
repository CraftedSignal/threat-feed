---
title: ApostropheCMS Authenticated SSRF via Rich-Text Widget Import (CVE-2026-45012)
slug: 2026-05-apostrophe-ssrf
description: ApostropheCMS is vulnerable to authenticated server-side request forgery (SSRF) via rich-text widget import; an attacker with edit access can trigger server-side requests to attacker-controlled URLs during widget validation, enabling internal port scanning and potential data exfiltration by re-hosting image-compatible responses.
date: "2026-05-14T18:27:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - apostrophecms
  - cve-2026-45012
vendors:
  - apostrophe
products:
  - apostrophecms <= 4.29.0
references:
  - https://github.com/advisories/GHSA-pr28-mf3q-qpg6
  - CVE-2026-45012
rules:
  - title: Detect ApostropheCMS SSRF via validate-widget
    description: Detects CVE-2026-45012 exploitation — POST requests to /api/v1/@apostrophecms/area/validate-widget with suspicious img src URLs
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
  - title: Detect ApostropheCMS Rich Text Widget Import with Data URI
    description: Detects suspicious rich text widget imports containing data URIs, which could be used for SSRF or other malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

ApostropheCMS versions 4.29.0 and earlier are vulnerable to an authenticated server-side request forgery (SSRF) vulnerability (CVE-2026-45012) within the rich-text widget import functionality. An authenticated user, possessing the ability to submit or edit rich-text widget content, can manipulate the import process to induce the server to issue requests to arbitrary URLs during widget validation. By injecting a crafted `<img src>` tag within the imported HTML, an attacker can trigger the server to fetch content from a specified URL. If the server receives an image-compatible response, ApostropheCMS may persist and re-host the fetched content, creating a vector for exfiltration of sensitive information. This vulnerability enables attackers to perform internal port scanning and potentially exfiltrate data.

## Attack Chain

1. An authenticated attacker logs into the ApostropheCMS application.
2. The attacker crafts a malicious rich-text widget payload containing an `import.html` attribute.
3. Within the `import.html`, the attacker includes an `<img src>` tag pointing to an attacker-controlled URL or internal resource.
4. The attacker submits the widget payload to the `/api/v1/@apostrophecms/area/validate-widget?aposMode=draft` endpoint.
5. The server-side `validate-widget` route parses the HTML content, identifies the `<img>` tag, and resolves the URL.
6. The server then performs an HTTP `fetch()` request to the resolved URL, as specified in the `src` attribute.
7. If the response is image-compatible, ApostropheCMS attempts to process and store the fetched content as an image asset.
8. The attacker can then access the re-hosted image through a generated image URL, potentially exfiltrating data. If the response is not an image, the SSRF still occurs and can be used for reconnaissance purposes.

## Impact

Successful exploitation of this SSRF vulnerability, tracked as CVE-2026-45012, allows authenticated users with rich-text widget editing privileges to trigger server-side requests to arbitrary URLs. This can enable attackers to scan internal network resources (127.0.0.1, private subnets), perform blind or semi-blind internal port and service discovery, and potentially exfiltrate data by causing the application to store and re-host fetched image content. The vulnerability affects ApostropheCMS versions 4.29.0 and earlier.

## Recommendation

*   Upgrade to a patched version of ApostropheCMS that addresses the SSRF vulnerability (CVE-2026-45012).
*   Deploy the Sigma rule `Detect ApostropheCMS SSRF via validate-widget` to detect requests to the vulnerable API endpoint with potentially malicious image URLs.
*   Monitor webserver logs for HTTP requests to internal or unusual destinations originating from the ApostropheCMS server.
*   Implement strict input validation and sanitization for user-supplied URLs, especially within rich-text widgets, to prevent the injection of malicious URLs.
