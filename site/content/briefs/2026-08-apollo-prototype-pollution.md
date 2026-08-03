---
title: Critical Prototype Pollution Vulnerability in Apollo Federation
slug: 2026-08-apollo-prototype-pollution
description: CVE-2026-32621 is a critical prototype pollution vulnerability in Apollo Federation that allows unauthenticated attackers to manipulate application objects via malicious GraphQL queries.
date: "2026-08-03T18:11:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Apollo
products:
  - Apollo Federation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2026-32621 targets Apollo Federation prototype pollution with a PoC exploit.
    confidence_band: high
cves:
  - id: CVE-2026-32621
    cvss: 9.9
    epss: 0.00512
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32621
  - https://github.com/advisories/GHSA-pfjj-6f4p-rvmh
  - https://sploitus.com/exploit?id=4F8338E0-9619-5812-893D-324A383C34D3
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=4F8338E0-9619-5812-893D-324A383C34D3
ioc_counts:
  url: 1
---

CVE-2026-32621 is a critical prototype pollution vulnerability (CWE-1321) affecting Apollo Federation gateways. The vulnerability resides in the deepMerge process, where an attacker can supply specially crafted GraphQL queries containing recursive keys such as __proto__, constructor, or prototype within field aliases or variable names. By exploiting this, an attacker can modify the base Object.prototype, causing subsequent requests to inherit malicious properties. This can lead to privilege escalation, unauthorized data access, or denial of service depending on the application context. The vulnerability has been assigned a CVSS score of 9.9, and working exploit code has been publicly released, significantly increasing the risk of exploitation for unpatched instances. Organizations using Apollo Federation should prioritize patching to the provided versions immediately.

## Attack Chain

1. Attacker crafts a GraphQL query containing object prototype keys like __proto__ or constructor inside a field alias.
2. Attacker sends the malicious GraphQL query to the Apollo Gateway endpoint (e.g., /graphql) via a standard HTTP POST request.
3. The Apollo Gateway receives the query and initiates the processing flow, forwarding the request to the relevant subgraph.
4. The subgraph returns a JSON response containing the malicious prototype keys.
5. The Apollo Gateway invokes its deepMerge() utility function to combine the response data.
6. The deepMerge() function incorrectly processes the prototype keys, resulting in the injection of properties directly into the global Object.prototype.
7. All subsequent operations handled by the gateway inherit the polluted properties from Object.prototype.
8. Attacker leverages these injected properties (e.g., isAdmin: true) to bypass authentication or execute arbitrary application logic.

## Impact

Successful exploitation allows attackers to alter the application state globally, potentially leading to full compromise of the gateway's security controls. Any downstream application relying on the object's integrity is affected. Public availability of an exploit increases the likelihood of widespread automated scanning and exploitation attempts against internet-facing GraphQL endpoints.

## Recommendation

1. Upgrade all Apollo Federation instances to versions 2.9.6, 2.10.5, 2.11.6, 2.12.3, or 2.13.2 immediately.
2. Implement request filtering at the Web Application Firewall (WAF) or API gateway layer to block GraphQL queries containing keys: __proto__, constructor, or prototype.
3. Review GraphQL schemas and validation logic to ensure strict adherence to allowed field aliases and variables.
4. Use Object.create(null) for data structures intended to hold external, untrusted input to prevent prototype inheritance.
