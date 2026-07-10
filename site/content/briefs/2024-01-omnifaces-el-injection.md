---
title: OmniFaces EL Injection Vulnerability via Crafted Resource Name
slug: 2024-01-omnifaces-el-injection
description: A server-side EL injection vulnerability exists in OmniFaces when using CDNResourceHandler with wildcard CDN mappings, allowing attackers to inject EL expressions in resource names leading to potential remote code execution, information disclosure, or denial of service.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - omnifaces
  - el-injection
  - rce
  - cdn
vendors:
  - OmniFaces
products:
  - OmniFaces
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Software Vulnerability Exploitation
references:
  - https://github.com/advisories/GHSA-vp6r-9m58-5xv8
rules:
  - title: OmniFaces EL Injection Attempt
    description: Detects attempts to exploit the OmniFaces EL injection vulnerability by identifying requests with EL expressions in the resource name.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: OmniFaces EL Injection URI
    description: Detects requests to resources containing EL-like syntax in the URI, potentially indicating an EL injection attempt in OmniFaces.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The OmniFaces framework, a utility library for JavaServer Faces (JSF), is susceptible to EL (Expression Language) injection when the `CDNResourceHandler` is configured with wildcard CDN mappings. This vulnerability allows an attacker to craft a malicious resource request URL by embedding an EL expression within the resource name. This expression is then evaluated server-side, potentially leading to Remote Code Execution (RCE), information disclosure, or denial of service. The vulnerability affects OmniFaces versions before 1.14.2, versions 2.0-RC1 to 2.7.32, versions 3.0-RC1 to 3.14.16, versions 4.0-M1 to 4.7.5, and versions 5.0-M1 to 5.2.2. Applications that only use explicit resource-to-URL mappings are not affected.

## Attack Chain

1. An attacker identifies an OmniFaces application utilizing `CDNResourceHandler` with a wildcard CDN mapping (e.g., `libraryName:*=https://cdn.example.com/*`).
2. The attacker crafts a malicious HTTP request targeting a resource served through the CDN.
3. The crafted request includes an EL expression embedded within the resource name part of the URL, such as `/javax.faces.resource/el_injection_${{...}}.js.xhtml?ln=libraryName`.
4. The `CDNResourceHandler` processes the request and extracts the resource name.
5. Due to the wildcard mapping, the handler attempts to resolve the resource location based on the provided name.
6. The EL expression within the resource name is inadvertently evaluated by the server's EL engine.
7. Depending on the EL implementation and accessible objects, the attacker can execute arbitrary code, access sensitive information, or trigger a denial-of-service condition.
8. The server responds to the attacker with the results of the EL expression evaluation (in case of information disclosure) or the effects of the executed code (in case of RCE).

## Impact

Successful exploitation of this vulnerability can have severe consequences. In the worst-case scenario, attackers can achieve Remote Code Execution (RCE), allowing them to gain complete control over the affected server. This control enables them to install malware, steal sensitive data, or disrupt services. Even without RCE, attackers can exploit the EL injection to disclose sensitive information or cause a denial of service by exhausting server resources. The impact varies based on the specific EL implementation and the objects available within the EL context, but any application using wildcard CDN mappings in vulnerable OmniFaces versions is at risk.

## Recommendation

*   Upgrade to the patched OmniFaces versions: 5.2.3, 4.7.5, 3.14.16, 2.7.32, and 1.14.2 to remediate the EL injection vulnerability as documented in the [GHSA advisory](https://github.com/advisories/GHSA-vp6r-9m58-5xv8).
*   Replace wildcard CDN mappings with explicit resource-to-URL mappings as a workaround if upgrading is not immediately feasible, as described in the [GHSA advisory](https://github.com/advisories/GHSA-vp6r-9m58-5xv8).
*   Implement a web application firewall (WAF) rule to detect and block requests containing suspicious EL expressions in the resource name part of the URL. Use the Sigma rule `OmniFaces EL Injection Attempt` as a starting point.
*   Monitor web server logs for unusual patterns in resource requests, specifically those containing EL-like syntax (e.g., `${...}`) in the URI query, as a general indicator of potential exploitation attempts and as covered by the Sigma rule `OmniFaces EL Injection URI`.
