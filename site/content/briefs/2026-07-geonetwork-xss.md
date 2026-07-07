---
title: GeoNetwork Reflected XSS through Client-Side Template Injection (CVE-2026-39379)
slug: 2026-07-geonetwork-xss
description: A reflected Cross-Site Scripting (XSS) vulnerability, CVE-2026-39379, exists in GeoNetwork due to client-side template injection within error pages, allowing an attacker to craft a URL that, when visited by a victim, causes arbitrary JavaScript to execute in their browser in the context of their authenticated session.
date: "2026-07-03T12:45:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - client-side-injection
  - angularjs
  - ghsa
  - webserver
vendors:
  - GeoNetwork
products:
  - GeoNetwork (3.0.0-3.12.12)
  - GeoNetwork (4.0.0-alpha.1-4.0.6)
  - GeoNetwork (4.2.0-4.2.14)
  - GeoNetwork (4.4.0-4.4.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker can trick a user (including an administrator) into visiting a crafted link.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: arbitrary JavaScript in the victim's browser (reflected Cross-Site Scripting via client-side template injection).
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: can be used to exfiltrate information
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: The resulting script execution runs in the context of the victim's authenticated session and can be used to...perform actions on the victim's behalf.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2v4m-fw6c-g78f
rules:
  - title: Detects CVE-2026-39379 Exploitation - GeoNetwork Reflected XSS Attempt
    description: Detects CVE-2026-39379 exploitation — common AngularJS client-side template injection patterns in the URI path or query of GeoNetwork web requests, which indicate attempts to trigger reflected XSS.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical reflected Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-39379, has been identified in GeoNetwork, an open-source geospatial metadata catalog. This flaw stems from improper neutralization of user-controlled input in error pages, which are built using AngularJS. When a user requests a non-existent or unauthorized service URL, GeoNetwork reflects parts of the original request directly into the error page without adequate sanitization. Since this page is an AngularJS application, an attacker can embed client-side template expressions (e.g., `{{...}}`) within the malicious URL. Upon rendering in the victim's browser, these expressions are evaluated, leading to the execution of arbitrary JavaScript. This vulnerability affects GeoNetwork versions 3.0.0 through 3.12.12, 4.0.0-alpha.1 through 4.0.6, 4.2.0 through 4.2.14, and 4.4.0 through 4.4.9. GeoNetwork 3.x and 4.0.x lines are no longer maintained and will not receive patches.

## Attack Chain

1.  **Craft Malicious URL**: The attacker crafts a specific URL that targets a non-existent or unauthorized GeoNetwork service endpoint, embedding client-side template injection payloads (e.g., `{{expression}}`) within the path or query parameters.
2.  **Phishing Delivery**: The attacker delivers this crafted malicious URL to a victim, typically via social engineering tactics such as phishing emails, instant messages, or compromised web pages, enticing the victim to click the link.
3.  **Victim Request**: The victim, interacting with the lure, clicks the malicious URL, causing their web browser to send an HTTP GET request containing the embedded payload to the vulnerable GeoNetwork server.
4.  **Server Error Response**: The GeoNetwork server processes the request for the invalid service. Due to its design, it generates an AngularJS-based error page that reflects portions of the original, unsanitized request URL back to the client.
5.  **Client-Side Template Evaluation**: When the victim's browser receives and renders the error page, the AngularJS framework identifies the reflected attacker-controlled content as a template expression. It then evaluates this expression.
6.  **Arbitrary JavaScript Execution**: The evaluation of the template expression results in the execution of the attacker's arbitrary JavaScript code within the context of the victim's browser.
7.  **Impact on Authenticated Session**: The malicious JavaScript executes with the same permissions and within the same authenticated session as the victim user, potentially allowing for session hijacking, data exfiltration from GeoNetwork, or performing unauthorized actions on the victim's behalf.
8.  **Further Exploitation**: The attacker leverages the executed JavaScript to achieve their objective, which could include redirecting the user to a fake login page for credential harvesting or initiating further attacks against the GeoNetwork instance.

## Impact

Successful exploitation of CVE-2026-39379 allows an attacker to execute arbitrary JavaScript code within the victim's browser. This code runs in the context of the victim's authenticated session, enabling severe consequences such as session hijacking, unauthorized data exfiltration from the GeoNetwork instance, or performing actions on the victim's behalf, including modifying content or changing configurations if the victim is an administrator. Additionally, attackers could inject fake login forms or malicious content to harvest credentials or spread malware. GeoNetwork versions 3.x and 4.0.x are particularly at risk as they are archived and will not receive official fixes, necessitating immediate upgrades for affected organizations.

## Recommendation

*   Patch CVE-2026-39379 immediately by upgrading GeoNetwork to a fixed version (4.2.15 or later, or 4.4.10 or later).
*   Deploy the Sigma rule "Detects CVE-2026-39379 Exploitation - GeoNetwork Reflected XSS Attempt" to your SIEM to identify attempts at client-side template injection via web server logs.
