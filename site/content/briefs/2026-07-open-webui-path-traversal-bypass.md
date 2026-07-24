---
title: Open WebUI Terminal Proxy Path Traversal Bypass via 9x Encoding (CVE-2026-59221)
slug: 2026-07-open-webui-path-traversal-bypass
description: An incomplete fix for a path traversal vulnerability in Open WebUI's terminal proxy allows authenticated attackers to bypass security checks by sending a 9x percent-encoded path, leading to requests being forwarded with terminal credentials and user identification headers to unintended arbitrary paths outside the intended proxy scope.
date: "2026-07-24T21:07:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:0.9.6:*:*:*:*:*:*:*
tags:
  - path-traversal
  - web-application
  - vulnerability
  - open-webui
  - defense-evasion
vendors:
  - Open WebUI
products:
  - Open WebUI (>= 0.9.6, < 0.10.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A user who has access to an admin-configured terminal connection can bypass the terminal proxy path traversal guard and cause Open WebUI to forward requests...
    confidence_band: high
cves:
  - id: CVE-2026-59221
    cvss: 7.7
    epss: 0.00362
references:
  - https://github.com/advisories/GHSA-frvj-c5qp-xj4w
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59221
rules:
  - title: Detects CVE-2026-59221 Exploitation - Open WebUI 9x Encoded Path Traversal
    description: Detects exploitation of CVE-2026-59221 where highly percent-encoded path traversal sequences (e.g., '..%2F' or '%2E%2E%2F') are used to bypass the Open WebUI terminal proxy's sanitization. This rule looks for 9 or more consecutive percent encodings of special characters.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1190
      - T1562
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-59221, has been identified in Open WebUI versions equal to or greater than 0.9.6 but less than 0.10.0. This flaw is a bypass of a previous security fix (GHSA-r2wg-2mcr-66rv) in the `_sanitize_proxy_path()` function within `backend/open_webui/routers/terminals.py`. The sanitizer is intended to decode URL paths until stable to prevent directory traversal but fails when confronted with a 9x percent-encoded path traversal payload, such as `../admin/system`. This allows authenticated users with access to an admin-configured terminal connection to bypass the path traversal guard. Attackers can leverage this to send requests with the configured terminal credentials and `X-User-Id` header to arbitrary paths outside the intended proxy destination, potentially leading to unauthorized access or actions on the upstream terminal server. This issue does not require a malicious terminal server or social engineering to modify settings; it only requires normal access to an existing configured terminal connection.

## Attack Chain

1. An authenticated attacker gains access to an existing configured terminal connection within the Open WebUI application.
2. The attacker crafts a path traversal payload, such as `../admin/system`, and encodes it nine times (e.g., `%2525...%252Fadmin%252Fsystem`).
3. The attacker sends an HTTP request containing this highly encoded payload as part of the URI path or query parameter to an Open WebUI terminal proxy endpoint.
4. The ASGI server hosting Open WebUI performs an initial decoding pass on the HTTP path before passing it to the application's `_sanitize_proxy_path()` function.
5. The `_sanitize_proxy_path()` function attempts to decode the path eight times, but the 9x encoded payload remains once-encoded after these passes.
6. The subsequent security checks, including `posixpath.normpath()` and `cleaned.startswith('..')`, are bypassed because the path still contains percent-encoded characters, which are treated as ordinary strings.
7. Open WebUI constructs a `target_url` using the inadequately sanitized path and forwards the request to the configured upstream terminal server, including sensitive `X-User-Id` headers and terminal credentials.
8. The upstream terminal server receives the request, fully decodes the path (e.g., `/base/../admin/system`), and processes it, allowing the attacker to access paths outside the intended `/base/` directory and potentially execute unauthorized commands or access sensitive data.

## Impact

Successful exploitation of CVE-2026-59221 enables authenticated users to bypass Open WebUI's terminal proxy path traversal guard. This allows attackers to redirect requests, including configured terminal credentials and the `X-User-Id` header, to arbitrary paths on the upstream terminal server that are outside the intended proxy scope. For orchestrator-backed connections, this bypass can also target sibling or parent routes after upstream decoding. This could lead to unauthorized access to system resources, execution of unauthorized commands, or manipulation of data on the terminal server. The vulnerability can be exploited by any user with normal access to a configured terminal connection, increasing the risk of insider threat or account compromise.

## Recommendation

* **Patch CVE-2026-59221**: Upgrade Open WebUI to version 0.10.0 or later as soon as it is available to address the incomplete sanitization logic.
* **Implement URI Path Sanitization Rule**: Deploy the provided Sigma rule to detect highly encoded path traversals in webserver logs targeting terminal proxy endpoints.
* **Monitor Webserver Logs**: Ensure comprehensive logging for web server access, specifically for `cs-uri-stem` and `cs-uri-query` fields, to identify unusual patterns of multi-percent-encoded characters.
* **Review Terminal Server Access**: Regularly audit access logs on configured terminal servers for requests originating from Open WebUI that target unusual or sensitive paths.
