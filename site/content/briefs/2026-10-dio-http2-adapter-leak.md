---
title: Sensitive Header Leak in dio_http2_adapter via Cross-Origin Redirects
slug: 2026-10-dio-http2-adapter-leak
description: The dio_http2_adapter library fails to sanitize Authorization, Cookie, and Proxy-Authorization headers when following cross-origin HTTP redirects, enabling credential theft.
date: "2026-10-15T22:24:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - credential-access
  - dart
  - flutter
products:
  - dio_http2_adapter
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The adapter's internal _fetch method constructs HTTP/2 request headers by unconditionally copying all entries from options.headers, leading to the disclosure of sensitive request headers upon redirect.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cr65-55v9-xhvv
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Software Engineering
  immediate_actions:
    - action: Review internal Dart/Flutter applications for use of dio_http2_adapter with default redirect behavior.
      owner: Software Engineering
      due: 48h
      evidence: The advisory notes the library is affected by default due to followRedirects default settings.
  mitigation_plan:
    - priority: immediate
      action: Patch dio_http2_adapter source to strip sensitive headers on cross-origin redirects.
      owner: Software Engineering
      addresses: Information Disclosure
      evidence: The provided source includes a specific patch diff for lib/src/http2_adapter.dart.
---

The `dio_http2_adapter` library, a plugin for the popular Dart `Dio` HTTP client, contains a vulnerability that leads to sensitive information disclosure. When the library is configured to follow HTTP redirects (which is enabled by default with a limit of 5), the adapter fails to perform origin validation before re-issuing a request to a new location. Consequently, sensitive request headers, specifically `Authorization`, `Cookie`, and `Proxy-Authorization`, are copied verbatim into the request sent to the redirect target, even if that target is on a completely different origin. 

This behavior essentially allows any malicious or compromised server that can trigger a `3xx` redirect to force the client to disclose authenticated session tokens or proxy credentials. The vulnerability resides in the `_fetch` method of the `Http2Adapter` class, where header maps are preserved during the `copyWith` operation without sanitization. This flaw impacts server-side Dart applications, mobile applications, and CLI tools utilizing `dio_http2_adapter` for authenticated HTTP/2 communications.

## Attack Chain

1. The victim application initiates an authenticated request using `Dio` with `Http2Adapter`, including sensitive headers like `Authorization` or `Cookie`.
2. The application contacts a malicious or compromised origin server that is under the attacker's control.
3. The malicious server responds with an HTTP `302 Found` (or other `3xx` status) and a `Location` header pointing to an attacker-controlled URI.
4. The `Http2Adapter` processes the `3xx` response, parsing the `Location` header to determine the new redirect target.
5. The adapter calls `options.copyWith` to initiate the new request to the redirect URI, inadvertently cloning the full original header map into the new request options.
6. No cross-origin check is performed to see if the new URI belongs to a different authority.
7. The `_fetch` method emits the new HTTP/2 request, now including the sensitive `Authorization` and `Cookie` headers, to the attacker-controlled server.
8. The attacker logs the incoming request headers at the final destination, successfully exfiltrating the victim's credentials.

## Impact

Successful exploitation allows for the unauthorized disclosure of sensitive credentials, including bearer tokens, session identifiers, and proxy authentication details. This enables attackers to impersonate the victim in subsequent requests to the original legitimate service. Given the prevalence of `Dio` in the Dart and Flutter ecosystems, any application using `dio_http2_adapter` with `followRedirects` enabled is at risk. The lack of authentication required to perform the redirect makes this a low-complexity attack for any adversary who can intercept or host an HTTP-based service.

## Recommendation

* Immediately upgrade or patch the `dio_http2_adapter` library logic to implement origin validation during redirect processing.
* For immediate mitigation, define a list of sensitive headers (e.g., `Authorization`, `Cookie`, `Proxy-Authorization`) and manually remove these headers from the `RequestOptions` when the redirect URI differs from the original request authority.
* Developers should ensure that their `Dio` configurations explicitly manage redirect behavior if full library updates are delayed, though this does not replace the need for the library-level sanitization fix.
* Organizations deploying Dart-based CLI tools or backend services should audit internal codebases to confirm if `dio_http2_adapter` is utilized for authenticated requests to untrusted or external endpoints.
