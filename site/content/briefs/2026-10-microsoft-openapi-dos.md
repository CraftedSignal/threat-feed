---
title: Uncontrolled Resource Consumption in Microsoft.OpenApi Libraries
slug: 2026-10-microsoft-openapi-dos
description: The Microsoft.OpenApi.YamlReader and Microsoft.OpenApi.Readers libraries are susceptible to a billion laughs denial-of-service attack, where crafted YAML files with nested anchors cause memory exhaustion and process termination during conversion.
date: "2026-10-14T22:21:55Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:microsoft:openapi.yamlreader:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:openapi.readers:*:*:*:*:*:*:*:*
vendors:
  - Microsoft
products:
  - Microsoft.OpenApi.YamlReader (2.0.0-preview.11 to < 2.12.0, 3.0.0 to < 3.10.0)
  - Microsoft.OpenApi.Readers (< 1.6.30)
cves:
  - id: CVE-2026-72923
    cvss: 7.5
    epss: 0.012
references:
  - https://github.com/advisories/GHSA-7pxr-59rr-hqj2
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-72923
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Microsoft.OpenApi.YamlReader to 1.6.30 or later
      owner: IT Operations
      due: 72h
      evidence: Source provides specific fixed version numbers
  mitigation_plan:
    - priority: immediate
      action: Isolate YAML parsing logic to a separate process to mitigate blast radius of OOM conditions
      owner: Security Engineering
      addresses: CVE-2026-72923
      evidence: Source documentation for secure parsing implementation
---

Microsoft.OpenApi.YamlReader and Microsoft.OpenApi.Readers are affected by an uncontrolled resource consumption vulnerability (CVE-2026-72923) that allows for a "billion laughs" style denial-of-service attack. The vulnerability exists within the conversion layer where YAML anchors and aliases are materialized as `JsonNode` instances. Because the conversion process lacks boundaries on recursion or node expansion, a small, maliciously crafted YAML document utilizing deeply nested anchors can trigger exponential memory allocation. This lead to Out-of-Memory (OOM) conditions and terminates the host application process. This vulnerability is highly relevant for any developer tools, CLIs, or services that parse OpenAPI documents provided by untrusted third parties.

## Impact

Successful exploitation results in the denial of service of any application utilizing these libraries to process untrusted OpenAPI YAML files. The impact is limited to service unavailability caused by process termination due to memory exhaustion. No evidence suggests remote code execution, authentication bypass, or data exfiltration.

## Recommendation

1. Upgrade Microsoft.OpenApi.YamlReader to version 2.12.0 or 3.10.0 immediately.
2. Upgrade Microsoft.OpenApi.Readers to version 1.6.30 or higher.
3. If immediate patching is not possible, evaluate the use of process-wide static properties `YamlConverter.MaxNodeCount` and `YamlConverter.MaxDepth` to enforce safer parsing limits.
4. Implement architecture-level isolation for parsing operations by offloading the parsing of untrusted OpenAPI documents to sandboxed or sidecar processes to limit the impact of potential crashes.
