---
title: Scriban `object.to_json` Uncontrolled Recursion DoS
slug: 2024-01-scriban-stack-overflow
description: The Scriban library is vulnerable to a denial-of-service attack where a specially crafted template with a self-referencing object passed to the `object.to_json` function causes unbounded recursion, leading to a `StackOverflowException` that terminates the .NET process.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - scriban
  - .net
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
  - https://github.com/advisories/GHSA-xcx6-vp38-8hr5
rules:
  - title: Detect Scriban StackOverflowException in Application Logs
    description: Detects StackOverflowException errors in application logs that are likely caused by the Scriban `object.to_json` vulnerability.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - application
      - windows|linux
  - title: Detect Process Terminations After Scriban Template Execution
    description: Detects unexpected process terminations following the execution of Scriban templates, which might indicate a StackOverflowException due to the `object.to_json` vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Scriban versions prior to 7.0.0 are susceptible to a denial-of-service vulnerability due to uncontrolled recursion in the `object.to_json` function. This function, used for recursive JSON serialization, lacks depth limits, circular reference detection, and stack overflow guards. A malicious Scriban template containing a self-referencing object, when processed by `object.to_json`, triggers unbounded recursion, leading to a `StackOverflowException` that terminates the hosting .NET process. This vulnerability poses a significant risk to applications embedding Scriban for user-provided templates, such as CMS platforms, email template engines, and static site generators. The vulnerability is easily exploitable, requiring only a single line of template code, and does not require authentication.

## Attack Chain

1. An attacker crafts a malicious Scriban template containing a self-referencing object. For example: `{{ x = {}; x.self = x; x | object.to_json }}`.
2. The template is submitted to an application that uses Scriban for template processing.
3. The Scriban engine parses the template and encounters the `object.to_json` function call.
4. The `ToJson()` function in `ObjectFunctions.cs` calls the vulnerable `WriteValue()` function.
5. `WriteValue()` attempts to serialize the self-referencing object without proper recursion checks.
6. Due to the self-reference, `WriteValue()` enters an infinite recursion loop.
7. Each recursive call consumes stack space, eventually leading to a `StackOverflowException`.
8. The `StackOverflowException` terminates the entire .NET process hosting the Scriban engine, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition, crashing the entire .NET process hosting the Scriban engine. Any application embedding Scriban for user-provided templates is vulnerable. Because `StackOverflowException` cannot be caught by application code, the hosting application cannot implement try/catch to survive this. This allows an unauthenticated attacker to trivially crash services using Scriban.

## Recommendation

- Upgrade to Scriban version 7.0.0 or later, which includes the fix for this vulnerability.
- If upgrading is not immediately feasible, consider implementing input validation and sanitization to prevent the use of self-referencing objects in Scriban templates.
- Monitor application logs for signs of `StackOverflowException` errors originating from Scriban template processing.
- Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
