---
title: LiquidJS Remote Code Execution Vulnerability
slug: 2026-05-liquidjs-rce
description: A remote code execution vulnerability exists in LiquidJS versions prior to 10.26.0, where crafted templates can execute arbitrary code by manipulating the `valueOf` filter and leveraging function calls via a comparable gadget.
date: "2026-05-27T18:28:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - template-injection
  - liquidjs
vendors:
  - npm
products:
  - liquidjs (< 10.26.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
references:
  - https://github.com/advisories/GHSA-gf2q-c269-pqgc
  - CVE-2026-45618
rules:
  - title: Detect LiquidJS RCE via Template Injection
    description: Detects CVE-2026-45618 exploitation — Attempts to exploit LiquidJS RCE by manipulating the `valueOf` filter within a template to execute arbitrary code.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
  - title: Detect LiquidJS RCE via File Read Attempt
    description: Detects CVE-2026-45618 exploitation — Attempts to read sensitive files via template manipulation in LiquidJS
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
rules_count: 2
---

A remote code execution vulnerability has been identified in LiquidJS, a template engine for JavaScript. This vulnerability, affecting versions prior to 10.26.0, allows attackers to execute arbitrary code by crafting malicious templates. The exploit involves manipulating the `valueOf` filter to gain access to the template context and then leveraging function calls through a comparable gadget. By overwriting key functions like `this.loader.lookup` and `this.readFile`, attackers can control the parsing process and ultimately obtain a reference to the `Function` constructor, enabling arbitrary code execution. This vulnerability poses a significant risk to applications using vulnerable versions of LiquidJS, potentially leading to complete system compromise. The vulnerability was published on 2026-05-27.

## Attack Chain

1. The attacker crafts a LiquidJS template containing malicious code.
2. The template uses the `valueOf` filter to gain access to the template context (`this`).
3. The attacker leverages the `group_by` filter to call functions via the comparable gadget.
4. The attacker uses `storeFn` to assign values within the template, targeting `fs.readFileSync`.
5. The attacker overwrites `this.loader.lookup` and `this.readFile` to control file parsing.
6. A reference to the `Function` constructor is obtained through manipulated filters.
7. The attacker crafts a payload to execute arbitrary code using the `Function` constructor.
8. The payload is executed, resulting in remote code execution on the server.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on systems running vulnerable versions of LiquidJS (versions prior to 10.26.0). This can lead to complete system compromise, including data theft, modification, or destruction, as well as the potential for lateral movement within the network. Given the critical nature of remote code execution, any application using LiquidJS is at high risk.

## Recommendation

- Upgrade LiquidJS to version 10.26.0 or later to patch CVE-2026-45618.
- Deploy the Sigma rule "Detect LiquidJS RCE via Template Injection" to identify exploitation attempts within your environment.
- Sanitize user-supplied templates to prevent injection of malicious code.
- Implement strict input validation to prevent attackers from controlling template content.
