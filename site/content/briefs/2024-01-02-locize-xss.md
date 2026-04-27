---
title: locize Client SDK Cross-Origin DOM XSS and Handler Hijack Vulnerability
slug: 2024-01-02-locize-xss
description: The locize client SDK versions prior to 4.0.21 are vulnerable to cross-origin DOM XSS and handler hijack due to missing origin validation in the InContext Editor, allowing attackers to inject malicious code and exfiltrate data via crafted postMessage events.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - xss
  - dom-xss
  - postMessage
  - locize
  - javascript
vendors:
  - locize
products:
  - locize client SDK
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://github.com/advisories/GHSA-w937-fg2h-xhq2
rules:
  - title: Detect Locize Client SDK DOM XSS Attempt via postMessage
    description: Detects potential DOM XSS attempts in the locize client SDK by monitoring for postMessage events that manipulate innerHTML or attributes.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - webserver
      - linux
  - title: Detect Locize API Hijack via postMessage
    description: Detects attempts to hijack the locize API source/origin by monitoring postMessage events to the isLocizeEnabled handler.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The locize client SDK, a browser module integrating the locize InContext translation editor, contains a cross-origin vulnerability in versions prior to 4.0.21. The vulnerability stems from the SDK's failure to validate the `event.origin` property when handling `window.addEventListener("message")` events. This allows a malicious webpage sharing a window reference with a locize-enabled host (e.g., via an iframe) to send crafted `postMessage` calls, triggering internal handlers without proper…
