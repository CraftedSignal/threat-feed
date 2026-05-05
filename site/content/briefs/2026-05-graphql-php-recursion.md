---
title: webonyx/graphql-php Unbounded Recursion Vulnerability
slug: 2026-05-graphql-php-recursion
description: The webonyx/graphql-php library has an unbounded recursion vulnerability in its parser that can lead to a stack overflow, causing a denial of service by terminating the PHP process with a SIGSEGV.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - graphql
  - denial-of-service
  - recursion
  - php
vendors:
  - webonyx
  - Laravel
  - Symfony
  - WordPress
  - Drupal
products:
  - graphql-php
  - Lighthouse
  - Overblog/GraphQLBundle
  - wp-graphql
  - Drupal GraphQL module
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-r7cg-qjjm-xhqq
rules:
  - title: Detect PHP Process Termination due to SIGSEGV
    description: Detects PHP-FPM child processes exiting with a SIGSEGV signal, indicating a possible stack overflow vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Large POST Requests to GraphQL Endpoint
    description: Detects unusually large POST requests to GraphQL endpoints, which may indicate an attempt to exploit the unbounded recursion vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `webonyx/graphql-php` library is vulnerable to unbounded recursion in its parser. This vulnerability, present in the `GraphQL\Language\Parser` component, allows an attacker to cause a denial-of-service (DoS) by sending a crafted GraphQL query with excessive nesting. The parser, lacking any recursion depth limit, exhausts the C stack, leading to a SIGSEGV signal and the termination of the PHP process. The smallest crashing payload is approximately 74 KB, making exploitation feasible. This issue affects version v15.31.4 and likely earlier versions due to the unchanged recursive descent parsing design. This vulnerability poses a significant risk to applications using the affected library, including those built with Laravel (Lighthouse), Symfony (Overblog/GraphQLBundle), WordPress (wp-graphql), and Drupal (Drupal GraphQL module).

## Attack Chain

1. An attacker crafts a malicious GraphQL query containing deeply nested structures, such as lists or objects.
2. The attacker sends the crafted GraphQL query to the web server hosting the vulnerable application.
3. The web server passes the query to the PHP application for processing.
4. The `GraphQL\Language\Parser` component within `webonyx/graphql-php` begins parsing the query using recursive descent methods.
5. Due to the excessive nesting, the parser's recursion depth increases without bound, consuming C stack memory.
6. The C stack is exhausted, triggering a SIGSEGV signal within the PHP runtime.
7. The PHP process terminates abruptly, interrupting any in-flight requests handled by that process.
8. The application becomes unavailable, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition. A single, relatively small (74 KB) POST request can terminate the PHP process handling it. In environments like php-fpm, this leads to worker processes being killed and respawned, dropping in-flight requests. Long-running PHP runtimes such as Swoole or RoadRunner will experience complete daemon failure. This occurs before any validation rules are applied, bypassing complexity analyzers and other defense mechanisms. The lack of a catchable error means there are no application-level logs or error messages generated, complicating incident response.

## Recommendation

*   Apply the recommended patch by the maintainers of `webonyx/graphql-php` when available, which introduces a recursion depth counter (Option 1 in the source).
*   As a temporary mitigation, consider implementing a front-end proxy or web application firewall (WAF) rule to limit the size of incoming GraphQL queries to prevent payloads exceeding 74KB.
*   Monitor PHP-FPM logs for "child exited on signal 11 (SIGSEGV)" messages to detect potential exploitation attempts.
*   Implement rate limiting on GraphQL endpoints to reduce the impact of potential DoS attacks.
