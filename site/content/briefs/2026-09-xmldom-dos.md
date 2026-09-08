---
title: Unauthenticated Denial of Service in xmldom via Quadratic Complexity
slug: 2026-09-xmldom-dos
description: The xmldom XML parser contains multiple O(n²) complexity flaws in its error-recovery path and DOM normalization logic, allowing an unauthenticated attacker to stall the Node.js event loop using crafted XML payloads.
date: "2026-09-08T21:53:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:xmldom_project:xmldom:*:*:*:*:*:*:*:*
  - cpe:2.3:a:xmldom_project:xmldom:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - web-application
products:
  - xmldom (all versions)
  - '@xmldom/xmldom (0.7.0 <= 0.8.14, 0.9.0 <= 0.9.11)'
cves:
  - id: CVE-2026-83614
    epss: 0.00351
references:
  - https://github.com/advisories/GHSA-93r5-fhx6-vmg9
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-83614
action_plan:
  priority: immediate_escalation
  owners:
    - Software Engineering
    - AppSec
  immediate_actions:
    - action: Upgrade @xmldom/xmldom to patched version
      owner: Software Engineering
      due: 24h
      evidence: Source provides specific vulnerable ranges and confirms fix for CVE-2026-83614
  mitigation_plan:
    - priority: immediate
      action: Enforce input size limits for XML parsing
      owner: AppSec
      addresses: CVE-2026-83614
      evidence: Source notes that quadratic complexity is triggered by input size
---

The `xmldom` library, commonly used for XML parsing in Node.js environments, is vulnerable to a denial of service (DoS) attack due to two distinct quadratic-time (O(n²)) complexity vulnerabilities. An attacker can supply a small, highly compressible XML document that exploits the parser's error-recovery path, leading to prolonged CPU exhaustion and event loop starvation. 

The first vulnerability occurs during the `parseElementStartPart` process, where the parser's error-recovery mechanism performs redundant character scanning when encountering specific malformed XML inputs. The second vulnerability exists within the `DOM.normalize()` method, which inefficiently merges adjacent text nodes created during the parsing recovery process. These issues are reachable through the default `DOMParser.parseFromString` method, and the `normalize()` flaw is also independently accessible via the public DOM API if an application builds a tree from untrusted input. These vulnerabilities affect the entire history of the project, including current 0.8.x and 0.9.x branches.

## Impact

Successful exploitation results in a persistent hang of the single-threaded Node.js event loop, preventing the application from processing any concurrent requests. Because the vulnerabilities are triggered by the default XML parser configuration and require no authentication, they represent a high risk to any service that accepts XML input from external sources. The attack is highly efficient, as payloads as small as 32 KB can cause multi-second stalls, which scale quadratically as document size increases.

## Recommendation

Prioritized actions for development and security teams:

- Update all dependencies using `xmldom` or `@xmldom/xmldom` to the patched versions immediately to remediate CVE-2026-83614.
- Implement strict input size limits for any endpoint accepting XML payloads to mitigate the impact of quadratic complexity attacks.
- Audit custom code that programmatically builds DOM trees using untrusted input, ensuring that `normalize()` is not called on unvalidated or deeply nested structures.
- Configure `DOMParser` with custom error handlers to identify and reject malformed input early, rather than relying on the default error-recovery path.
