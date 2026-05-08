---
title: Open-WebUI Stored XSS Vulnerability via Model Description
slug: 2026-05-open-webui-xss
description: 'Open-WebUI is vulnerable to stored cross-site scripting (XSS) where an authenticated user with model creation permissions can inject a malicious model description containing a javascript: URI within a markdown link that, when clicked, executes arbitrary JavaScript in another user''s browser, potentially leading to session hijacking; this affects versions v0.3.5 through v0.8.12.'
date: "2026-05-08T19:00:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:0.3.8:*:*:*:*:*:*:*
tags:
  - xss
  - open-webui
  - web-application
vendors:
  - npm
  - pip
products:
  - open-webui (<= 0.8.12)
cves:
  - id: CVE-2024-7990
    cvss: 8.4
    epss: 0.00293
references:
  - https://github.com/advisories/GHSA-gf5m-wcrh-7928
rules:
  - title: Detect Open-WebUI Model Creation with Javascript URI
    description: 'Detects the creation of Open-WebUI models with descriptions containing javascript: URIs, indicating a potential XSS attack.'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
  - title: Detect Open-WebUI Token Exfiltration via HTTP Server Logs
    description: Detects potential Open-WebUI access token exfiltration attempts by monitoring HTTP server logs for access attempts containing 'localStorage.token'.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - webserver
rules_count: 2
---

Open-WebUI versions v0.3.5 through v0.8.12 are susceptible to a stored cross-site scripting (XSS) vulnerability. This flaw allows authenticated users with model creation permissions to inject malicious JavaScript code into the model description field. When other users, including administrators, view the affected model's description in the chat UI and click the specially crafted markdown link, the injected JavaScript code executes within their browsers. This can lead to session hijacking, sensitive data theft, or other unauthorized actions. The vulnerability stems from insufficient sanitization of user-supplied model descriptions before rendering them in the user interface. The issue is resolved in version v0.9.0. This vulnerability is distinct from CVE-2024-7990, as it leverages a different bypass mechanism involving markdown links with javascript: URIs.

## Attack Chain

1. An attacker authenticates to the Open-WebUI instance with an account that has model creation permissions (workspace.models).
2. The attacker crafts a malicious model description containing a markdown link with a `javascript:` URI (e.g., `[text](javascript:alert())`).
3. The attacker uses the `/api/v1/models/create` endpoint to create a new model with the malicious description.
4. The Open-WebUI application stores the unsanitized model description in the database.
5. A victim user (including an administrator) navigates to the chat UI and views the model with the malicious description.
6. The application retrieves the model description from the database and renders it using `sanitizeResponseContent`, `replaceAll('\n', '<br>')`, `marked.parse()`, and `{@html ...}`.
7. The `marked.parse()` function converts the markdown link into an `<a href="javascript:...">` HTML element.
8. The victim user clicks on the malicious link, triggering the execution of the JavaScript code within their browser. This could exfiltrate the user's access token via a crafted `javascript:` url.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code within the context of a victim's browser. This can lead to a variety of malicious outcomes, including session hijacking, theft of sensitive information (such as access tokens), defacement of the user interface, and potentially, remote code execution if combined with other vulnerabilities. Given the ability to steal admin tokens, attackers can create new tools to execute arbitrary code, which impacts all Open-WebUI users.

## Recommendation

*   Upgrade Open-WebUI to version v0.9.0 or later, where the output of `marked.parse()` is wrapped with `DOMPurify.sanitize()` to mitigate the XSS vulnerability.
*   Deploy the Sigma rule "Detect Open-WebUI Model Creation with Javascript URI" to identify attempts to create models with malicious descriptions.
*   Review existing model descriptions for suspicious content, particularly markdown links with `javascript:` URIs, and remove or sanitize any identified malicious entries.
