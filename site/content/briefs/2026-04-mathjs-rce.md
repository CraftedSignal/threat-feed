---
title: Math.js Improperly Controlled Modification of Object Attributes Leads to RCE
slug: 2026-04-mathjs-rce
description: A vulnerability in math.js versions before 15.2.0 allows for arbitrary JavaScript execution through the expression parser when evaluating user-supplied expressions.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - mathjs
  - rce
  - expression-injection
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-jvff-x2qm-6286
  - https://github.com/josdejong/mathjs/releases/tag/v15.2.0
rules:
  - title: Detect Math.js Expression Injection Attempt via HTTP Query
    description: Detects potential expression injection attempts in math.js applications by monitoring HTTP query parameters for suspicious patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Math.js Expression Injection Attempt via HTTP Body
    description: Detects potential expression injection attempts in math.js applications by monitoring HTTP request body for suspicious patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Math.js is a popular open-source mathematics library for JavaScript. A critical vulnerability (GHSA-jvff-x2qm-6286) exists in versions prior to 15.2.0, allowing arbitrary JavaScript execution. This flaw stems from improperly controlled modification of dynamically-determined object attributes within the expression parser. Applications that utilize math.js to evaluate user-provided mathematical expressions are susceptible. The vulnerability was reported on April 10, 2026, and a patch was released…
