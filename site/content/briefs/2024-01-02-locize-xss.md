---
title: locize Client SDK Cross-Origin DOM XSS and Handler Hijack Vulnerability
slug: 2024-01-02-locize-xss
description: The locize client SDK versions prior to 4.0.21 are vulnerable to cross-origin DOM XSS and handler hijack due to missing origin validation in the InContext Editor, allowing attackers to inject malicious code and exfiltrate data via crafted postMessage events.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
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

The locize client SDK, a browser module integrating the locize InContext translation editor, contains a cross-origin vulnerability in versions prior to 4.0.21. The vulnerability stems from the SDK's failure to validate the `event.origin` property when handling `window.addEventListener("message")` events. This allows a malicious webpage sharing a window reference with a locize-enabled host (e.g., via an iframe) to send crafted `postMessage` calls, triggering internal handlers without proper authorization. Successful exploitation can lead to DOM-based XSS, hijacking of the `api.source` and `api.origin` properties, and CSS injection, potentially compromising the confidentiality and integrity of the application. This vulnerability was discovered via an internal security audit of the locize ecosystem.

## Attack Chain

1.  An attacker hosts a malicious webpage with the intent to exploit a locize-enabled application.
2.  The locize-enabled application embeds the attacker's page as an iframe or has a `window.opener`/`window.open` relationship with it.
3.  The attacker crafts a `postMessage` with a `sender` field equal to `"i18next-editor-frame"` and a malicious payload targeted at specific handlers.
4.  The locize SDK's `window.addEventListener("message")` handler receives the message and, without validating `event.origin`, dispatches it to the internal handlers.
5.  If the attacker targets the `editKey` or `commitKeys` handlers, the attacker-controlled payload values are assigned to `item.node.innerHTML` or `item.node.setAttribute(attr, value)`, injecting malicious scripts or HTML.
6.  If the attacker targets the `isLocizeEnabled` handler, the `api.source` and `api.origin` are hijacked, redirecting subsequent messages to the attacker's window and exfiltrating translation content.
7.  If the attacker targets the `requestPopupChanges` handler, malicious CSS code is injected into the popup's inline style.
8.  The attacker gains unauthorized access to sensitive data or injects malicious content into the locize-enabled application, impacting its integrity and confidentiality.

## Impact

Successful exploitation of this vulnerability can lead to several critical consequences. Cross-origin DOM XSS allows arbitrary code execution within the context of the vulnerable application. Hijacking `api.source` and `api.origin` results in the leakage of translation content and metadata to the attacker, compromising sensitive information. CSS injection can alter the visual appearance of the application, potentially leading to phishing attacks or further exploitation. The number of victims depends on the adoption rate of vulnerable locize SDK versions prior to 4.0.21.

## Recommendation

*   Upgrade to `locize` client SDK version 4.0.21 or later to patch the vulnerability. This version implements `event.origin` validation in `src/api/postMessage.js`, mitigating the risk of cross-origin attacks.
*   Deploy the Sigma rule "Detect Locize Client SDK DOM XSS Attempt via postMessage" to identify exploitation attempts based on manipulation of `innerHTML` or `setAttribute` in the locize context.
*   Enable web server logging and monitor for suspicious `postMessage` events originating from unexpected domains to detect potential exploitation attempts targeting the locize SDK.
