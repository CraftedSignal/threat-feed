---
title: HAXcms Cross-Tenant Account Takeover via Stored XSS and Token Exposure
slug: 2026-05-haxcms-token-exfil
description: HAXcms is vulnerable to stored XSS and exposes authentication tokens in the `/system/api/connectionSettings` endpoint, allowing an attacker to perform cross-tenant account takeover by injecting malicious JavaScript to steal the `jwt`, `user_token`, `site_token`, and `appstore_token`.
date: "2026-05-19T14:48:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - haxcms
  - xss
  - account-takeover
vendors:
  - HAXtheWeb
products:
  - haxcms-nodejs (<= 25.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
references:
  - https://github.com/advisories/GHSA-x3x5-7h4h-gwxg
  - CVE-2026-46511
rules:
  - title: Detect HAXcms Connection Settings Request
    description: Detects requests to the `/system/api/connectionSettings` endpoint, potentially indicating an attempt to steal authentication tokens.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - webserver
  - title: Detect HAXcms Token Exfiltration via Webhook
    description: Detects attempts to exfiltrate HAXcms tokens to external webhooks, indicating potential account takeover.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
rules_count: 2
---

HAXcms is vulnerable to a critical account takeover vulnerability stemming from a combination of stored XSS and insecure token handling. The vulnerability, present in versions 25.0.0 and earlier, allows an authenticated attacker to inject malicious JavaScript code into a page that, when viewed by another user, exfiltrates that user's authentication tokens. The `/system/api/connectionSettings` endpoint dynamically leaks sensitive tokens into a global JavaScript variable (`window.appSettings`), which can be accessed and stolen via XSS. This vulnerability allows for complete cross-tenant account hijacking, enabling attackers to perform administrative actions without needing the victim's password.

## Attack Chain

1.  Attacker authenticates to the HAXcms application with valid credentials.
2.  Attacker injects malicious JavaScript code via a stored XSS vulnerability, such as within an iframe's `srcdoc` or through a `<video-player>` tag, on a page they have write access to.
3.  The victim user views the compromised page.
4.  The injected JavaScript executes in the victim's browser context.
5.  The JavaScript fetches the victim's connection settings via `fetch('/<username>/system/api/connectionSettings')`, which includes the victim's valid JWT and tokens.
6.  The JavaScript parses the `jwt`, `user_token`, `site_token`, and `appstore_token` from the response.
7.  The JavaScript encodes the stolen tokens (including `jwt`, `user_token`, `site_token`, and `appstore_token`) using Base64 encoding.
8.  The JavaScript exfiltrates the encoded tokens to an attacker-controlled webhook using an image request to bypass CORS. The attacker now has the ability to impersonate the victim and perform administrative actions.

## Impact

This vulnerability allows for complete account hijacking. An attacker who successfully exploits this vulnerability can impersonate a victim user without needing their password. This gives the attacker the ability to perform malicious administrative actions, such as creating or deleting sites, modifying user access, and uploading malicious content. The reliance on `window.appSettings` for storing long-lived administrative tokens creates a critical vulnerability when combined with XSS.

## Recommendation

*   Deploy the Sigma rule `Detect HAXcms Connection Settings Request` to detect requests to the `/system/api/connectionSettings` endpoint from unusual sources, and tune for your environment.
*   Deploy the Sigma rule `Detect HAXcms Token Exfiltration via Webhook` to detect attempts to exfiltrate the tokens to external webhooks.
*   Ensure that all HAXcms instances are updated to a patched version that addresses this vulnerability to prevent CVE-2026-46511 exploitation.
