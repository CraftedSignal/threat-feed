---
title: FlightPHP Sensitive Information Disclosure via Default Error Handler
slug: 2024-01-flightphp-info-disclosure
description: The default error handler in FlightPHP core writes the full exception message, exception code, and stack trace directly into the HTTP 500 response, disclosing sensitive information such as internal paths, secrets, and application structure.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - web-application
  - flightphp
vendors:
  - composer
products:
  - flightphp/core (< 3.18.1)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Reconnaissance
    technique_id: T1592
    technique_name: Gather Victim Host Information
references:
  - https://github.com/advisories/GHSA-qrch-52m5-vv85
rules:
  - title: FlightPHP Sensitive Information Disclosure in HTTP Response
    description: Detects HTTP 500 responses containing potentially sensitive information disclosed by FlightPHP's default error handler.
    platform: sigma
    severity: high
    tactics:
      - reconnaissance
    techniques:
      - T1592.002
    data_sources:
      - webserver
      - linux
  - title: FlightPHP Potential Secret Leakage in HTTP Response
    description: Detects HTTP 500 responses from FlightPHP that may contain leaked secrets.
    platform: sigma
    severity: critical
    tactics:
      - reconnaissance
    techniques:
      - T1592.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The FlightPHP framework, prior to version 3.18.1, is vulnerable to sensitive information disclosure due to its default error handling mechanism. The `Engine::_error()` function writes the full exception message, exception code, and stack trace directly into the HTTP 500 response without any debug gating. This behavior can expose internal filesystem paths, secrets interpolated into exception messages (such as database credentials or API tokens), and the application's module structure. The vulnerability was discovered by @Rootingg and a proof of concept is available, demonstrating the leakage of sensitive information. This disclosure can provide attackers with valuable primitives for chaining other weaknesses, such as Local File Inclusion (LFI) or path traversal vulnerabilities. The issue is resolved in version 3.18.1 with the introduction of a `flight.debug` setting to control the verbosity of error output.

## Attack Chain

1. An attacker identifies a FlightPHP application running a version prior to 3.18.1.
2. The attacker crafts a request designed to trigger an uncaught exception within the application. This could be through invalid input, resource exhaustion, or other error-inducing actions.
3. The application's error handler, `Engine::_error()`, is invoked.
4. The error handler formats the exception message, code, and stack trace into an HTML response.
5. This response includes absolute filesystem paths, potentially revealing the application's directory structure.
6. The response may also include secrets, such as database credentials or API keys, if these are inadvertently included in exception messages.
7. The HTTP 500 response is sent to the attacker's browser, containing the sensitive information.
8. The attacker uses the disclosed information to further exploit the application, potentially leveraging LFI or path traversal vulnerabilities to gain unauthorized access or execute arbitrary code.

## Impact

Successful exploitation of this vulnerability can lead to the disclosure of sensitive information, including absolute filesystem paths, database credentials, API tokens, and internal application structure. This information can be used to facilitate further attacks, such as Local File Inclusion (LFI) or path traversal vulnerabilities. The disclosure of database credentials or API tokens could grant attackers unauthorized access to sensitive data or systems. The vulnerability affects applications using FlightPHP versions prior to 3.18.1.

## Recommendation

*   Upgrade FlightPHP to version 3.18.1 or later to patch the vulnerability. The fix introduces a `flight.debug` setting that gates the verbose output, preventing sensitive information from being exposed in production environments.
*   Deploy the Sigma rule "FlightPHP Sensitive Information Disclosure in HTTP Response" to detect instances of verbose error messages in HTTP 500 responses.
*   Review application code to ensure that sensitive information, such as database credentials and API tokens, are not inadvertently included in exception messages.
*   Enable webserver logging (category: webserver, product: linux/windows) to capture HTTP requests and responses, facilitating detection and analysis of potential exploitation attempts.
