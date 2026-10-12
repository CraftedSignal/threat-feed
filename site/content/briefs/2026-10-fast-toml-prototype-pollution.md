---
title: Prototype Pollution Vulnerability in fast-toml
slug: 2026-10-fast-toml-prototype-pollution
description: The fast-toml library up to version 0.5.4 is vulnerable to prototype pollution, allowing attackers to modify Object.prototype through crafted TOML input, potentially leading to denial of service or authorization bypass.
date: "2026-10-12T22:40:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fast-toml_project:fast-toml:*:*:*:*:*:node.js:*:*
tags:
  - prototype-pollution
  - supply-chain
  - vulnerability
products:
  - fast-toml (<= 0.5.4)
cves:
  - id: CVE-2021-48012
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-48012
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Engineering
  immediate_actions:
    - action: Inventory fast-toml usage and update to patched version
      owner: Development
      due: 48h
      evidence: CVE-2021-48012 vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Update or replace fast-toml to mitigate CVE-2021-48012
      owner: Development
      addresses: CVE-2021-48012
      evidence: NVD advisory for CVE-2021-48012
---

The fast-toml library (all versions through 0.5.4) contains a prototype pollution vulnerability that allows attackers to manipulate the base Object.prototype. By supplying TOML data containing specific key segments such as "__proto__", "constructor", or "prototype", an attacker can influence the behavior of all objects within the JavaScript runtime. Specifically, passing "[__proto__]" or "[constructor.prototype]" as table headers, or using "__proto__.x" as dotted keys during the parse() process, triggers the vulnerability. This flaw poses a significant risk to applications that process untrusted TOML data, as it can be leveraged to achieve authorization bypass or cause denial of service conditions by disrupting expected object properties.

## Impact

Successful exploitation allows for the modification of the global Object.prototype, which can cause downstream application logic errors, denial of service, or authorization bypasses in environments utilizing fast-toml to process external or untrusted data. There is no specific victim sector reported, but any node-based application relying on this dependency for configuration or data parsing is at risk.

## Recommendation

Prioritized actions for development and security engineering teams:
- Identify all instances of the fast-toml dependency within the software bill of materials (SBOM) and update to a version beyond 0.5.4 if a patch is available.
- Implement input validation on all TOML data processed by the application to explicitly reject keys containing "__proto__", "constructor", or "prototype".
- Perform dependency auditing to determine if fast-toml is included as a transitive dependency in other packages.
