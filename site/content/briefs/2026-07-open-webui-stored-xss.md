---
title: Open WebUI Vulnerable to Stored Cross-Site Scripting (XSS) via iFrame in Citations Model
slug: 2026-07-open-webui-stored-xss
description: An authenticated attacker can achieve stored Cross-Site Scripting (XSS) in Open WebUI by manually modifying chat history requests to inject malicious HTML into citation document metadata, leading to session takeover or potential Remote Code Execution (RCE) on the server if an administrator is targeted.
date: "2026-07-07T16:56:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-application
  - vulnerability
  - client-side-injection
  - open-webui
products:
  - Open WebUI (pip/open-webui < 0.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Manually modifying chat history allows setting the `html` property within document metadata.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: Observe the payload is rendered in the iFrame and the javascript executes.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Admins are at risk of exposing the server to RCE via same chain described in https://github.com/advisories/GHSA-w7xj-8fx7-wfch.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-xc8p-9rr6-97r2
---

Open WebUI is vulnerable to a high-severity stored Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-26192, stemming from insecure iFrame rendering in its citation model. An authenticated attacker can exploit this by intercepting and modifying HTTP requests when saving chat history to inject malicious HTML content into document metadata, specifically by adding `html: true` and embedding an XSS payload. When another user, particularly an administrator, views a citation containing this weaponized document within a shared chat, the vulnerable Open WebUI frontend renders the content in an iFrame with insufficient sandboxing (`allow-scripts` and `allow-same-origin` are hardcoded), allowing the XSS payload to execute. This can lead to session hijacking, exfiltration of sensitive information, or, in the case of an administrator, potential server-side Remote Code Execution (RCE) by leveraging other known vulnerabilities. The vulnerability affects `pip/open-webui` versions prior to 0.7.0.

## Attack Chain

1.  An authenticated attacker logs into Open WebUI and initiates a new chat session.
2.  The attacker attaches an arbitrary file as a "document source" to the chat.
3.  While saving the chat history or message, the attacker uses an HTTP proxy tool (e.g., Burp Suite, Caido, ZAP) to intercept the outgoing save request.
4.  Within the intercepted request's JSON body, the attacker locates the object corresponding to the document source within the `history` and `messages` objects.
5.  The attacker modifies this object by adding `html: true` to its metadata and injects an XSS payload (e.g., `<script>alert(document.cookie)</script>`) into the document content field.
6.  The attacker forwards the modified HTTP request, causing the Open WebUI server to store the malicious chat history with the embedded XSS payload.
7.  The attacker shares the link to this weaponized chat with a victim user (e.g., via a phishing link).
8.  When the victim accesses the shared chat and clicks on the malicious document citation, the Open WebUI frontend renders the content in an insecure iFrame, executing the attacker's JavaScript payload in the victim's browser context.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary client-side JavaScript code in the context of the victim's browser session. For low-privilege users, this can lead to session takeover, allowing the attacker to read session tokens from local storage and exfiltrate them to an attacker-controlled server. If an administrator is targeted and views the malicious citation, the XSS payload can be used to bypass security controls and potentially achieve server-side Remote Code Execution (RCE) by chaining with other known vulnerabilities, as described in GHSA-w7xj-8fx7-wfch. This poses a significant risk to the integrity and confidentiality of data within the Open WebUI environment.

## Recommendation

*   **Patch CVE-2026-26192 immediately:** Upgrade all Open WebUI installations to version 0.7.0 or newer to mitigate the vulnerability.
*   **Implement Web Application Firewall (WAF) rules:** Configure a WAF to inspect `POST` requests to chat history save endpoints for unusual modifications like the addition of `html: true` in JSON bodies, and block requests containing common XSS payload patterns in document content, though this may require product-specific WAF configuration for JSON body inspection.
*   **Educate users on phishing awareness:** Warn users about suspicious shared chat links or messages that encourage clicking on document citations from unknown or untrusted sources.
