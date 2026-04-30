---
title: 'CVE-2026-22729: JSONPath Injection Vulnerability in Spring AI''s PgVectorStore'
slug: 2024-06-spring-ai-jsonpath-injection
description: CVE-2026-22729 is a JSONPath Injection vulnerability found in Spring AI's PgVectorStore, potentially allowing for unauthorized data access or modification.
date: "2026-03-19T12:35:09Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-22729
  - jsonpath-injection
  - spring-ai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.reddit.com/r/netsec/comments/1rxz7tl/cve202622729_jsonpath_injection_in_spring_ais/
  - https://blog.securelayer7.net/cve-2026-22729-jsonpath-injection-spring-ai-pgvectorstore/
rules:
  - title: Detect Suspicious JSONPath Expressions in Process Arguments
    description: Detects processes with command-line arguments containing potentially malicious JSONPath expressions indicative of injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Traffic Containing Suspicious JSONPath Payloads
    description: Detects network traffic with HTTP requests containing potentially malicious JSONPath expressions in the URI or body.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-22729 is a newly identified JSONPath Injection vulnerability affecting the PgVectorStore component within the Spring AI framework. The vulnerability arises from insufficient input sanitization when processing JSONPath expressions, potentially allowing attackers to inject malicious code into queries. Successful exploitation could lead to unauthorized data access, modification, or even remote code execution depending on the application's configuration and permissions. This vulnerability…
