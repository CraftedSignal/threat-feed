---
title: Prototype Pollution Vulnerability in Style Dictionary convertTokenData Function
slug: 2026-07-style-dictionary-pollution
description: A prototype pollution vulnerability exists in the Style Dictionary library, specifically within the `convertTokenData()` utility function, allowing malicious users to exploit it by crafting a token array containing `__proto__` keys, which, when processed, will globally pollute the `Object.prototype`, impacting NodeJS server applications and web applications.
date: "2026-07-28T22:23:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - supply-chain
  - npm
  - nodejs
vendors:
  - Style Dictionary
products:
  - Style Dictionary (>= 4.3.0, < 5.4.4)
cves:
  - id: CVE-2026-54639
    cvss: 8.8
    epss: 0.00132
references:
  - https://github.com/advisories/GHSA-vj5c-m527-mpff
  - https://github.com/style-dictionary/style-dictionary/pull/1702
  - https://styledictionary.com/reference/config/#expand
  - https://styledictionary.com/reference/utilities/convert-token-data/
---

A significant prototype pollution vulnerability, tracked as CVE-2026-54639, has been identified in the Style Dictionary library, affecting versions `>=4.3.0` but prior to `5.4.4`. This flaw resides within the `convertTokenData()` utility function. An attacker can exploit this by introducing a specially crafted token array, for instance, `[{ key: '{__proto__.foo}', value: 'malicious' }]`. When this malicious input is processed by the vulnerable function, it leads to a global pollution of the `Object.prototype`. This means that any object subsequently created within the application's runtime will inherit the injected `foo` property with an attacker-controlled value. The vulnerability can be triggered directly via `convertTokenData()`, indirectly through Style Dictionary's Expand API, or during its transform lifecycle. This poses a high risk to NodeJS server applications and a moderate risk to web applications using Style Dictionary, allowing for potential manipulation of application logic, bypass of security controls, or data tampering.

## Attack Chain

1. An attacker identifies a target application using Style Dictionary versions `>=4.3.0` and `<5.4.4`.
2. The attacker crafts a malicious token data structure, such as `[{ key: '{__proto__.foo}', value: 'malicious' }]`, containing a key that targets the JavaScript `__proto__` property.
3. The crafted token data is introduced into the vulnerable application, for example, through an untrusted configuration file, API endpoint, or user-controlled input.
4. The application processes the malicious token data, either by directly invoking the `convertTokenData()` utility function, or indirectly via Style Dictionary's `Expand API` or `transform lifecycle` mechanisms.
5. Due to insufficient sanitization and validation within the `convertTokenData()` function, the specially crafted `__proto__` key is processed.
6. The `Object.prototype` is globally polluted, injecting a new property (`foo`) with an attacker-defined value (`malicious`) into all newly created objects, potentially leading to arbitrary code execution or logic manipulation.

## Impact

The impact of this prototype pollution vulnerability varies depending on the application context. For NodeJS server applications integrating Style Dictionary, the impact is considered high, as global object modification can lead to severe consequences, including remote code execution, denial of service, or data manipulation. For web applications, the impact is rated as moderate, potentially leading to client-side attacks like cross-site scripting (XSS) or data exfiltration. In scenarios where the user of Style Dictionary also maintains the tokens and access is strictly controlled, the impact is low. Successful exploitation can enable attackers to manipulate application behavior, bypass authentication or authorization checks, or inject malicious properties into system-level objects, compromising the integrity and security of the affected application.

## Recommendation

* Patch CVE-2026-54639 immediately by upgrading the `npm/style-dictionary` package to version `5.4.4` or higher.
* Implement the provided workaround by sanitizing all token data recursively to check for object keys containing `__proto__` before processing them with Style Dictionary.
* Ensure that, if using the workaround, the `expand` configuration option in Style Dictionary is explicitly set to `false` to prevent indirect exploitation pathways.
