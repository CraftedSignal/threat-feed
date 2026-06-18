---
title: spomky-labs/otphp Unbounded Digits Parameter Leads to Denial of Service
slug: 2026-06-otphp-divisionbyzero
description: The spomky-labs/otphp library is vulnerable to a denial of service (GHSA-g7m4-839x-ch6v) where an unbounded 'digits' parameter in an otpauth provisioning URI causes a DivisionByZeroError, leading to unhandled fatal errors in applications trying to generate or verify OTPs.
date: "2026-06-18T20:54:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - php
  - denial-of-service
  - vulnerability
  - ghsa
vendors:
  - Spomky-Labs
products:
  - otphp < 11.4.3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Application Denial of Service
references:
  - https://github.com/advisories/GHSA-g7m4-839x-ch6v
rules:
  - title: Detect GHSA-g7m4-839x-ch6v OTPHPH Vulnerability Exploitation Attempt
    description: Detects attempts to exploit the spomky-labs/otphp DivisionByZeroError vulnerability (GHSA-g7m4-839x-ch6v) by passing an otpauth URI with an excessively large 'digits' parameter (>=40) within a web request. This can lead to application denial of service.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
  - title: Detect Potential OTP Application Denial of Service (HTTP 5xx Response)
    description: Detects HTTP 5xx server errors on web endpoints commonly associated with OTP verification. While generic, a spike can indicate a denial of service due to vulnerabilities like GHSA-g7m4-839x-ch6v or other application logic errors impacting OTP processing.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 2
---

The `spomky-labs/otphp` library, versions prior to 11.4.3, is affected by a high-severity denial-of-service vulnerability (GHSA-g7m4-839x-ch6v) concerning its handling of OTP provisioning URIs. This vulnerability, disclosed in June 2026, arises when the `digits` parameter within an `otpauth` URI is provided with an excessively large value (typically 40 or greater). The library's internal validation for this parameter only checks for a lower bound, lacking an upper bound. During OTP generation or verification, the calculation `10 ** digits` overflows PHP's integer capacity on 64-bit systems, resulting in an implicit cast to `0`. A subsequent modulo operation with this zero value triggers a `DivisionByZeroError`. Critically, this error extends PHP's `Error` class rather than `Exception`, meaning it bypasses typical `try-catch (\Exception)` blocks, leading to unhandled fatal errors and effectively causing a denial of service for any application component attempting to process the malformed OTP object.

## Attack Chain

1.  An attacker crafts a malicious `otpauth` provisioning URI containing an unusually large `digits` parameter, for example, `otpauth://totp/Alice?secret=JBSWY3DPEHPK3PXP&digits=50`.
2.  A vulnerable PHP application, utilizing `spomky-labs/otphp` (versions prior to 11.4.3), processes this URI, for instance, by calling `OTPHP\Factory::loadFromProvisioningUri()`.
3.  The `loadFromProvisioningUri()` function internalizes the attacker-controlled `digits` parameter, which bypasses validation due to the lack of an upper bound check.
4.  Later, the application attempts to generate or verify an OTP by invoking methods like `at()`, `now()`, or `verify()` on the `OTPHP\OTP` object created from the malicious URI.
5.  During the OTP calculation within `src/OTP.php:283`, the expression `10 ** $this->getDigits()` is evaluated using the excessively large `digits` value.
6.  On 64-bit PHP 8.x, for `digits` values around 40 or higher, the exponentiation `10 ** digits` results in an integer overflow, causing PHP to implicitly cast the result to `0`.
7.  A subsequent modulo operation, `($code % 0)`, attempts to divide by zero, which triggers a `DivisionByZeroError`.
8.  As `DivisionByZeroError` is a PHP `Error` (not an `Exception`), it typically bypasses standard error handling, leading to an unhandled fatal error and causing a denial of service for the affected application component.

## Impact

The vulnerability can lead to an application-level denial of service. When an application attempts to process a maliciously crafted `otpauth` URI, the internal `DivisionByZeroError` leads to an unhandled fatal error, effectively crashing the OTP generation or verification process. This means that users might be unable to log in, perform multi-factor authentication, or complete any transaction relying on OTPs, rendering the affected service partially or fully unavailable. While no specific victim counts are provided, any PHP application utilizing the vulnerable `spomky-labs/otphp` library for OTP functionality could be impacted.

## Recommendation

*   Upgrade the `spomky-labs/otphp` library to version 11.4.3 or newer immediately to mitigate the vulnerability (GHSA-g7m4-839x-ch6v).
*   Deploy the Sigma rule "Detect GHSA-g7m4-839x-ch6v OTPHPH Vulnerability Exploitation Attempt" to your web application firewall (WAF) or intrusion detection system (IDS) to block web requests containing suspicious `otpauth` URIs with large `digits` parameters.
*   Implement the Sigma rule "Detect Potential OTP Application Denial of Service (HTTP 5xx Response)" and tune it for high-volume HTTP 5xx responses on OTP-related endpoints as a general indicator of potential DoS.
*   Enable comprehensive application logging for PHP errors and monitor for `DivisionByZeroError` messages, particularly those originating from `spomky-labs/otphp` components.
