---
title: mcp-from-openapi SSRF Vulnerability via Untrusted OpenAPI Specifications
slug: 2026-04-mcp-from-openapi-ssrf
description: The mcp-from-openapi library is vulnerable to Server-Side Request Forgery (SSRF) due to insecure handling of $ref pointers in OpenAPI specifications, allowing attackers to read local files, internal network resources, and cloud metadata endpoints by processing untrusted OpenAPI specifications.
date: "2026-04-08T19:22:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - openapi
  - mcp-from-openapi
references:
  - https://github.com/advisories/GHSA-v6ph-xcq9-qxxj
iocs:
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  - type: url
    value: http://127.0.0.1:9997/ssrf-proof
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

The `mcp-from-openapi` library, up to version 2.1.2, is susceptible to Server-Side Request Forgery (SSRF) attacks. This vulnerability arises from the library's use of `@apidevtools/json-schema-ref-parser` to dereference `$ref` pointers in OpenAPI specifications without implementing any URL restrictions or custom resolvers. By crafting malicious OpenAPI specifications, an attacker can exploit this flaw to force the library to fetch internal network addresses, cloud metadata endpoints (like `http://169.254.169.254/`), or local files using `file:///etc/passwd`. This occurs during the `initialize()` call when processing the OpenAPI definition. Defenders should be aware that applications utilizing `mcp-from-openapi` to process potentially untrusted OpenAPI specifications are at risk.

## Attack Chain

1. An attacker crafts a malicious OpenAPI specification containing `$ref` pointers to internal resources, cloud metadata endpoints, or local files.
2. The application using `mcp-from-openapi` receives this crafted OpenAPI specification, for example, via user upload or network request.
3. The `OpenAPIToolGenerator.initialize()` function is called, triggering the `$ref` dereferencing process.
4. The `json-schema-ref-parser` library, lacking proper configuration, fetches the resources specified in the malicious `$ref` pointers.
5. If the `$ref` points to a cloud metadata endpoint (e.g., `http://169.254.169.254/`), the server attempts to retrieve sensitive cloud credentials.
6. If the `$ref` points to an internal service, the server probes the internal network, potentially revealing information about available services.
7. If the `$ref` points to a local file (e.g., `file:///etc/passwd`), the server reads the contents of the file and includes it in the dereferenced output.
8. The attacker gains access to sensitive information, such as cloud credentials or internal network configurations, enabling further exploitation or lateral movement.

## Impact

Successful exploitation of this SSRF vulnerability in `mcp-from-openapi` can have significant consequences. Attackers can steal cloud credentials by targeting metadata endpoints like `http://169.254.169.254/`, allowing them to compromise cloud infrastructure. The vulnerability also enables internal network scanning by probing internal services and ports, mapping out the internal network layout. Furthermore, attackers can read arbitrary files from the server's filesystem using the `file://` protocol, potentially gaining access to sensitive configuration files or credentials. The affected packages include npm/mcp-from-openapi (vulnerable: <= 2.1.2), npm/@frontmcp/sdk (vulnerable: <= 1.0.3), and npm/@frontmcp/adapters (vulnerable: <= 1.0.3).

## Recommendation

*   Upgrade `mcp-from-openapi` to a patched version if available, or implement a patch to restrict URL resolution as described in the suggested fix.
*   Implement input validation on OpenAPI specifications before processing them with `mcp-from-openapi` to prevent malicious `$ref` values, mitigating CVE-2026-39885.
*   Monitor network connections originating from processes running `mcp-from-openapi`, alerting on connections to internal network addresses or cloud metadata endpoints using the network connection rule below.
*   Deploy the Sigma rule that detects access to local files via the `file://` protocol to your SIEM and tune it for your environment.
