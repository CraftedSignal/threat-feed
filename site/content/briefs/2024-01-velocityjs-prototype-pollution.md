---
title: 'Velocity.js Prototype Pollution Vulnerability via #set Directive (CVE-2026-44966)'
slug: 2024-01-velocityjs-prototype-pollution
description: 'A prototype pollution vulnerability exists in Velocity.js versions 2.1.5 and earlier, allowing attackers to modify Object.prototype via crafted #set directives in Velocity templates, potentially leading to Denial of Service (DoS) or Remote Code Execution (RCE).'
date: "2026-05-09T00:40:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - vulnerability
  - velocity.js
  - CVE-2026-44966
products:
  - velocityjs <= 2.1.5
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-j658-c2gf-x6pq
rules:
  - title: Detect Velocity.js Prototype Pollution Attempt via set Directive
    description: 'Detects CVE-2026-44966 exploitation — An attacker attempts to pollute the Object.prototype using a #set directive within a Velocity template.'
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detect Velocity.js Prototype Pollution Attempt via POST Data
    description: 'Detects CVE-2026-44966 exploitation — An attacker attempts to pollute the Object.prototype using a #set directive within a Velocity template submitted via POST data.'
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 2
---

A prototype pollution vulnerability has been identified in Velocity.js, specifically affecting versions 2.1.5 and earlier. The vulnerability, designated as CVE-2026-44966, stems from improper input validation within the `#set` directive's path assignment logic in Velocity templates. This flaw allows an attacker to manipulate the `Object.prototype` if they can influence the content of a Velocity template being rendered by an application. Successful exploitation could lead to a Denial of Service (DoS) or, depending on the server environment's configuration, Remote Code Execution (RCE). The vulnerability was reported on May 9, 2026. Applications utilizing Velocity.js to render templates based on user-supplied or externally influenced data are most at risk.

## Attack Chain

1.  The attacker identifies a Velocity template rendering endpoint within an application.
2.  The attacker crafts a malicious Velocity template containing a `#set` directive that targets the `Object.prototype`. Specifically, the template includes a payload like `#set($__proto__.polluted = "hacked")`.
3.  The attacker injects the malicious template into the application, either by directly supplying the template content, manipulating template variables, or exploiting other injection points.
4.  The Velocity engine processes the malicious template, and the `#set` directive is executed.
5.  Due to the lack of input validation on the path within the `#set` directive, the engine directly assigns the attacker-controlled value to the `Object.prototype`.
6.  The `Object.prototype` is now polluted, meaning all JavaScript objects inherit the attacker-defined property and value.
7.  The application's behavior becomes unpredictable, potentially leading to a Denial of Service as the polluted prototype disrupts normal operations.
8.  In certain environments, the prototype pollution can be chained with other vulnerabilities (e.g., gadget chains) to achieve Remote Code Execution (RCE).

## Impact

This vulnerability allows an attacker to pollute the `Object.prototype` in Velocity.js applications. The impact of successful exploitation ranges from Denial of Service (DoS) to Remote Code Execution (RCE), depending on the specific environment and application logic. Any application using Velocity.js version 2.1.5 or earlier is potentially vulnerable if it renders templates that can be influenced by untrusted users. Prototype pollution can bypass security controls and cause unexpected application behavior.

## Recommendation

*   Upgrade to a patched version of Velocity.js that addresses the prototype pollution vulnerability.
*   Sanitize user-supplied data used in Velocity templates to prevent the injection of malicious `#set` directives targeting `Object.prototype`.
*   Deploy the Sigma rule "Detect Velocity.js Prototype Pollution Attempt via set Directive" to identify attempts to exploit CVE-2026-44966 in web server logs.
*   Implement input validation on template variables to prevent the use of special characters like `__proto__` or `constructor` that could be used for prototype pollution.
*   Monitor web server logs for suspicious POST requests to Velocity template rendering endpoints with payloads containing `__proto__` in the query parameters, as detected by the Sigma rule.
