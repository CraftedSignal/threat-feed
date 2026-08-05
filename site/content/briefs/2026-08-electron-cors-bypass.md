---
title: Electron CORS Protection Bypass via Custom Schemes
slug: 2026-08-electron-cors-bypass
description: A vulnerability in Electron (CVE-2026-70604) allows remote origins to bypass CORS protections when interacting with custom schemes, enabling unauthorized read access to sensitive data.
date: "2026-08-05T21:26:17Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Electron
products:
  - Electron (39.x, 40.x, 41.x, 42.x)
cves:
  - id: CVE-2026-70604
    cvss: 7.4
references:
  - https://github.com/advisories/GHSA-v3j7-r9gq-3gjw
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70604
---

Electron has disclosed a security vulnerability identified as CVE-2026-70604, affecting applications that utilize custom protocol schemes. The issue arises when a custom scheme is registered with `supportFetchAPI: true` but fails to enable `corsEnabled: true`. Under these conditions, the Electron framework fails to enforce Cross-Origin Resource Sharing (CORS) policies. 

This architectural flaw allows a remote origin, if loaded within a renderer process, to perform `fetch()` or `XMLHttpRequest` operations against the custom scheme. Consequently, the remote origin can read the full response body of these requests, leading to potential data exfiltration of sensitive information processed by the local application. The vulnerability impacts multiple versions across the 39.x, 40.x, 41.x, and 42.x branches. Defenders should note that applications are only affected if they load untrusted content within their renderer processes and fail to explicitly enable CORS for these schemes.

## Impact

Successful exploitation allows for unauthorized cross-origin read access to sensitive data handled by the application's internal custom protocols. This can result in the exfiltration of user session tokens, local configuration files, or sensitive business data processed by the Electron-based application. The severity of the impact depends on the sensitivity of the data served by the custom protocol and the extent to which the application displays third-party or untrusted web content.

## Recommendation

* Upgrade to patched versions: 39.8.10, 40.9.3, 41.4.0, or 42.0.0.
* Audit application code for registrations of custom protocols using the `protocol` module; ensure that `corsEnabled` is set to `true` for any scheme serving sensitive data.
* Implement strict `Origin` header validation within protocol handler functions to ensure that only authorized origins can access sensitive data.
* Disable the loading of remote, untrusted content in renderer processes wherever possible to eliminate the attack vector.
