---
title: ChilliCream GraphQL Platform Stack Overflow via Deeply Nested GraphQL Documents
slug: 2024-01-03-chillichream-graphql-stack-overflow
description: ChilliCream GraphQL Platform is vulnerable to a stack overflow exception due to unbounded recursion depth in the Utf8GraphQLParser; a crafted GraphQL document with deeply nested elements can trigger a StackOverflowException, terminating the worker process.
date: "2024-01-03T18:29:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - graphql
  - stack-overflow
  - denial-of-service
  - hotchocolate
vendors:
  - ChilliCream
products:
  - Hot Chocolate
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1213
    technique_name: Exploit API
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-qr3m-xw4c-jqw3
  - https://github.com/ChilliCream/graphql-platform/pull/9528
rules:
  - title: Detect GraphQL Stack Overflow Attempt via HTTP Request Size
    description: Detects abnormally large HTTP requests to GraphQL endpoints, potentially indicating a stack overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect GraphQL Stack Overflow Attempt via HTTP Compression Ratio
    description: Detects abnormally high HTTP compression ratios for GraphQL requests, which may indicate deeply nested structures.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Frequent Application Restarts
    description: Detects frequent application restarts, which may be a symptom of the GraphQL stack overflow vulnerability exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - application
      - kubernetes
rules_count: 3
---

The ChilliCream GraphQL Platform, specifically the Hot Chocolate library, is susceptible to a critical vulnerability stemming from the `Utf8GraphQLParser`. This parser, lacking recursion depth limits, can be exploited by a malicious actor sending crafted GraphQL documents containing deeply nested selection sets, object values, list values, or list types. Successful exploitation leads to a `StackOverflowException`, an uncatchable error in .NET, which immediately terminates the worker process. This occurs before established validation rules like `MaxExecutionDepth` or complexity analyzers can engage, rendering them ineffective. Payloads as small as 40KB can trigger this vulnerability. Patches have been released to address this issue in versions 12.22.7, 13.9.16, 14.3.1, and 15.1.14. This vulnerability poses a significant threat to the availability of affected GraphQL services.

## Attack Chain

1. An attacker crafts a malicious GraphQL document with deeply nested elements (selection sets, object values, list values, or list types) to exploit the lack of recursion depth limits in the `Utf8GraphQLParser`.
2. The attacker sends the crafted GraphQL document as an HTTP request to the GraphQL endpoint of a vulnerable ChilliCream Hot Chocolate application.
3. The `Utf8GraphQLParser.Parse` method is invoked to parse the incoming GraphQL document.
4. Due to the deeply nested structure of the malicious document, the recursive descent parser enters an uncontrolled recursion, rapidly consuming stack space.
5. The recursion continues until a `StackOverflowException` is triggered, exceeding the stack limit.
6. Because `StackOverflowException` is uncatchable in .NET, the entire worker process is immediately terminated.
7. All in-flight HTTP requests, background `IHostedService` tasks, and open WebSocket subscriptions on that worker are dropped, leading to denial of service.
8. The orchestrator (Kubernetes, IIS, etc.) detects the terminated process and restarts it, but the vulnerability can be re-exploited, leading to a persistent denial-of-service condition.

## Impact

The primary impact of this vulnerability is denial of service. Exploitation leads to the immediate termination of the worker process handling GraphQL requests. All active requests, background tasks, and WebSocket subscriptions are dropped. Since the exception is uncatchable, a restart is required, which an attacker can trigger repeatedly. A relatively small, crafted payload of around 40KB can be used to trigger the vulnerability. The sectors most affected are those relying on ChilliCream GraphQL Platform for critical services.

## Recommendation

*   Immediately upgrade the `HotChocolate.Language` NuGet package to the patched versions: 12.22.7, 13.9.16, 14.3.1, or 15.1.14, as indicated in the advisory to remediate CVE-2026-40324.
*   Implement request body size limits at the reverse proxy or load balancer layer as a defense-in-depth measure. Be aware that the smallest crashing payload is 40KB, and it is highly compressible.
*   Monitor application logs for frequent unexpected process terminations, which could indicate exploitation attempts.
