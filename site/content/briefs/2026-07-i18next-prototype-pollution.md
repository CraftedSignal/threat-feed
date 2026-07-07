---
title: i18next-http-middleware Prototype Pollution via missingKeyHandler (CVE-2026-48714)
slug: 2026-07-i18next-prototype-pollution
description: A critical prototype pollution vulnerability (CVE-2026-48714) exists in `i18next-http-middleware` versions up to 3.9.6, where the `missingKeyHandler` fails to adequately sanitize dotted key segments, allowing attackers to manipulate `Object.prototype` when exposed to untrusted input and used with vulnerable `i18next-fs-backend` versions up to 2.6.5, potentially leading to configuration poisoning, security bypasses, crashes, or remote code execution.
date: "2026-07-03T10:46:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:i18next:i18next-http-middleware:*:*:*:*:*:node.js:*:*
tags:
  - web-vulnerability
  - prototype-pollution
  - npm
  - nodejs
products:
  - i18next-http-middleware (< 3.9.7)
  - i18next-fs-backend (< 2.6.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Applications that expose `missingKeyHandler` to untrusted input AND use `i18next-fs-backend` ≤ 2.6.5 are directly exploitable for remote prototype pollution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Depending on the host application, polluted prototype properties may cause crashes, corrupted translation behaviour, configuration poisoning, or bypasses of property-based security checks. (Implies potential for RCE).
    confidence_band: med
cves:
  - id: CVE-2026-48714
    cvss: 9.1
    epss: 0.00419
references:
  - https://github.com/advisories/GHSA-f49m-vf83-692w
  - https://github.com/i18next/i18next-fs-backend/security/advisories/GHSA-2933-q333-qg83
rules:
  - title: Detects CVE-2026-48714 Exploitation — i18next Prototype Pollution
    description: Detects exploitation attempts against CVE-2026-48714, where `i18next-http-middleware`'s `missingKeyHandler` is abused for prototype pollution via dotted '__proto__' keys in HTTP POST requests.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1587
    data_sources:
      - webserver
rules_count: 1
---

A critical prototype pollution vulnerability, identified as CVE-2026-48714, affects `i18next-http-middleware` versions 3.9.6 and earlier. This flaw specifically impacts the `missingKeyHandler`, which is designed to process keys for missing translations. While previous versions introduced denylists for literal unsafe keys like `__proto__`, this vulnerability arises because the handler failed to block dotted variants, such as `"__proto__.polluted"`. When applications expose this `missingKeyHandler` to untrusted user input and are combined with vulnerable backend packages like `i18next-fs-backend` versions 2.6.5 or earlier, an attacker can exploit this oversight. The `keySeparator` (default `.`) within these backends splits the malicious key, passing it to an unguarded `setPath()` function that then directly writes to `Object.prototype`. Successful exploitation can lead to severe consequences including application crashes, corrupted translation behavior, configuration poisoning, and bypasses of property-based security checks, with potential for remote code execution. Patches are available in `i18next-http-middleware 3.9.7` and `i18next-fs-backend 2.6.6`.

## Attack Chain

1.  **Reconnaissance & Target Identification**: An attacker identifies a web application utilizing `i18next-http-middleware` and `i18next-fs-backend` with an exposed `missingKeyHandler` endpoint that accepts untrusted input.
2.  **Vulnerability Confirmation**: The attacker sends test requests to confirm the application's response to various keys, probing for the behavior of the `missingKeyHandler`.
3.  **Craft Malicious Request**: The attacker crafts a specially designed HTTP POST request targeting the exposed `missingKeyHandler` endpoint, including a malicious key in the request body, such as `"__proto__.polluted=value"`.
4.  **Handler Processing**: The `i18next-http-middleware` receives the request and passes the malicious key to its `missingKeyHandler` function.
5.  **Key Segmentation**: Inside the `missingKeyHandler` (or the downstream backend), the configured `keySeparator` (typically `.`) splits the `"__proto__.polluted"` key into segments.
6.  **Prototype Pollution**: The segmented key, including `__proto__`, is then passed to an unguarded `setPath()` function within `i18next-fs-backend` or a similarly affected backend, which inadvertently writes a new property onto `Object.prototype`.
7.  **Application Impact**: The modified `Object.prototype` pollutes the global object, leading to unexpected application behavior, crashes, configuration poisoning, or the bypass of security checks, potentially enabling further remote execution or data exfiltration.

## Impact

This vulnerability directly impacts applications that leverage `i18next-http-middleware` with an exposed `missingKeyHandler` to untrusted inputs, specifically when paired with `i18next-fs-backend` versions up to 2.6.5. Successful exploitation allows attackers to perform remote prototype pollution, enabling them to inject arbitrary properties into `Object.prototype`. The observed damage can range from application crashes and corrupted translation functionality to critical configuration poisoning and the bypass of property-based security controls. Depending on the specific application logic, this can escalate to full remote code execution, granting attackers control over the compromised system and access to sensitive data.

## Recommendation

*   **Patch CVE-2026-48714**: Immediately upgrade `i18next-http-middleware` to version 3.9.7 or later to address CVE-2026-48714.
*   **Patch Companion Vulnerability**: Upgrade `i18next-fs-backend` to version 2.6.6 or later, as it contains a root-cause fix for companion advisory GHSA-2933-q333-qg83.
*   **Restrict Access to `missingKeyHandler`**: If immediate patching is not possible, mount the `missingKeyHandler` behind authentication or remove the route entirely to prevent untrusted users from accessing it.
*   **Implement Request Filtering**: Add a request-body filter ahead of the `missingKeyHandler` to reject any top-level key containing `__proto__`, `constructor`, or `prototype` after splitting on the configured `keySeparator`.
*   **Disable Missing-Key Persistence**: When accepting writes from untrusted input, disable missing-key persistence by setting `saveMissing: false` in your i18next configuration.
*   **Deploy Sigma Rules**: Deploy the provided Sigma rule to your SIEM to detect attempts at exploiting CVE-2026-48714 via the `missingKeyHandler` endpoint.
