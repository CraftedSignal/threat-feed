---
title: mcp-from-openapi SSRF Vulnerability via Untrusted OpenAPI Specifications
slug: 2026-04-mcp-from-openapi-ssrf
description: The mcp-from-openapi library is vulnerable to Server-Side Request Forgery (SSRF) due to insecure handling of $ref pointers in OpenAPI specifications, allowing attackers to read local files, internal network resources, and cloud metadata endpoints by processing untrusted OpenAPI specifications.
date: "2026-04-08T19:22:53Z"
severities:
  - high
tags:
  - ssrf
  - openapi
  - mcp-from-openapi
references:
  - https://github.com/advisories/GHSA-v6ph-xcq9-qxxj
ioc_counts:
  url: 2
rules:
  - title: Detect mcp-from-openapi SSRF via Local File Access
    description: Detects attempts to read local files using the file:// protocol within the mcp-from-openapi library, indicative of SSRF vulnerability CVE-2026-39885 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - windows
  - title: Detect mcp-from-openapi SSRF to Cloud Metadata Endpoint
    description: Detects attempts to access common cloud metadata endpoints, indicative of SSRF vulnerability CVE-2026-39885 exploitation via mcp-from-openapi.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The `mcp-from-openapi` library, up to version 2.1.2, is susceptible to Server-Side Request Forgery (SSRF) attacks. This vulnerability arises from the library's use of `@apidevtools/json-schema-ref-parser` to dereference `$ref` pointers in OpenAPI specifications without implementing any URL restrictions or custom resolvers. By crafting malicious OpenAPI specifications, an attacker can exploit this flaw to force the library to fetch internal network addresses, cloud metadata endpoints (like…
