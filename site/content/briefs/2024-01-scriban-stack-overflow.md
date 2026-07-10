---
title: Scriban Stack Overflow via Nested Array Initializers
slug: 2024-01-scriban-stack-overflow
description: Scriban versions before 7.0.0 are vulnerable to a stack overflow exception due to deeply nested array initializers bypassing the ExpressionDepthLimit, leading to uncontrolled recursion and process termination when parsing templates with untrusted input, similar to GHSA-wgh7-7m3c-fx25.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - scriban
  - stack-overflow
  - denial-of-service
  - template-injection
vendors:
  - Scriban
products:
  - Scriban
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-p6q4-fgr8-vx4p
rules:
  - title: Detect Scriban Stack Overflow Attempt via Nested Array Initializers
    description: Detects attempts to exploit the Scriban stack overflow vulnerability by identifying deeply nested array initializers in templates.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Scriban Template Parsing with Excessive Recursion
    description: Detects potential stack overflow exploitation attempts by monitoring for unusual call stack depth within Scriban template parsing operations.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Scriban, a .NET templating engine, is susceptible to a stack overflow vulnerability in versions prior to 7.0.0. This flaw arises from the insufficient protection against deeply nested array initializers within Scriban templates. Specifically, the fix implemented for GHSA-wgh7-7m3c-fx25, which introduced an `ExpressionDepthLimit`, does not effectively prevent recursion through the `ParseArrayInitializer` function when handling such nested structures. The vulnerability can be triggered by crafting malicious templates containing deeply nested array initializers (e.g., `[[[[...`). Exploitation leads to a `StackOverflowException`, abruptly terminating the process and potentially causing denial-of-service conditions in applications utilizing Scriban for template processing. The vulnerability impacts any application calling `Template.Parse` with untrusted input, even with the `ExpressionDepthLimit` enabled.

## Attack Chain

1. An attacker crafts a Scriban template containing deeply nested array initializers (e.g., `{{[[[[[...1]]]]]}}`).
2. The application utilizes the `Template.Parse` method from the Scriban library to parse the attacker-controlled template.
3. During parsing, the `ParseArrayInitializer` function is invoked to handle the array initializer.
4. `ParseArrayInitializer` recursively calls `ParseExpression` to evaluate the nested expressions within the array.
5. `ParseExpression` calls `ParseArrayInitializer` again, creating a recursive loop.
6. This recursion continues without being limited by the `ExpressionDepthLimit`, which is designed to prevent uncontrolled recursion in other parsing paths.
7. The excessive recursion consumes stack memory, eventually leading to a `StackOverflowException`.
8. The `StackOverflowException` cannot be caught in .NET, resulting in immediate termination of the application process, causing a denial-of-service.

## Impact

The stack overflow vulnerability in Scriban can lead to denial-of-service attacks. Successful exploitation results in immediate process termination of the application using the Scriban library to parse templates. This vulnerability impacts any application that utilizes Scriban to process potentially untrusted template input. Given the nature of a StackOverflowException, the impact is severe as it abruptly halts the affected service, which could affect availability and stability. This is especially critical in web applications or services that rely on template parsing for rendering content or processing user inputs.

## Recommendation

*   Upgrade to Scriban version 7.0.0 or later to address the vulnerability (reference: Affected Packages).
*   Implement input validation and sanitization to prevent the parsing of templates from untrusted sources that may contain deeply nested array initializers (reference: Overview).
*   Deploy the Sigma rule to detect attempts to exploit this vulnerability by monitoring for abnormally deep expression nesting during Scriban template parsing (reference: rules).
*   Review and harden any existing Scriban template parsing implementations to ensure that they are not processing untrusted input directly (reference: Overview).
