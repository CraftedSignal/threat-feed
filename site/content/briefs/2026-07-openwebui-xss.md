---
title: Open WebUI Stored XSS via iFrame Embeds (CVE-2026-26193)
slug: 2026-07-openwebui-xss
description: A stored Cross-Site Scripting (XSS) vulnerability exists in Open WebUI versions up to 0.6.43, allowing attackers to manually modify chat history to inject malicious content into response messages via iFrames with misconfigured sandboxing, leading to arbitrary script execution, potential session hijacking, and enabling Remote Code Execution (RCE) on the server for administrators.
date: "2026-07-07T16:55:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-application
  - open-webui
  - cve
vendors:
  - Open WebUI
products:
  - Open WebUI (<= 0.6.43)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows for execution of arbitrary scripts
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Low privilege users are at risk of having their session taken over by a payload that reads their token from local storage and exfiltrates it to an attacker controlled server.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: payload that reads their token from local storage and exfiltrates it to an attacker controlled server
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any user can create a weaponised chat that can be shared and subsequently used to target other users.
    confidence_band: high
cves:
  - id: CVE-2026-26193
    cvss: 7.3
    epss: 0.00198
references:
  - https://github.com/advisories/GHSA-vjm7-m4xh-7wrc
---

A critical stored Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-26193, has been discovered in Open WebUI versions up to and including 0.6.43. This flaw allows attackers to inject malicious code into chat response messages by manually manipulating the chat history to set a user-controlled `embeds` property. The injected content is rendered within an iFrame whose sandbox attributes (`allow-scripts` and `allow-same-origin`) are hardcoded as true, effectively nullifying security protections. This bypass enables arbitrary JavaScript execution in the context of the user's browser. The vulnerability poses a significant risk as it can lead to session hijacking for low-privilege users by exfiltrating local storage tokens, and for administrators, it could pave the way for Remote Code Execution (RCE) on the server, as highlighted by related vulnerabilities. The malicious chat can be persistently stored and subsequently shared with other users, allowing the attack to propagate across the platform.

## Attack Chain

1.  **Initial Access / Pre-computation**: An attacker with legitimate user access to Open WebUI initiates a new chat session or interacts with an existing one.
2.  **Manipulation**: The attacker edits a model's response within a chat, preparing to inject malicious content.
3.  **Request Interception**: Using an HTTP proxy tool (e.g., Burp Suite, Caido, ZAP), the attacker intercepts the HTTP POST request sent to the server to save the modified chat history.
4.  **Payload Injection**: Within the intercepted request body, the attacker locates the specific `messages` object corresponding to the edited text and manually adds an `embeds` key containing a malicious JavaScript payload.
5.  **Persistence**: The manipulated HTTP request, now containing the XSS payload, is forwarded to the Open WebUI server, which saves the chat history, persistently storing the malicious content.
6.  **Exploitation**: Upon refreshing the chat page or when another user views the shared malicious chat, the Open WebUI frontend renders the stored `embeds` content within an iFrame.
7.  **Sandbox Bypass & Execution**: Due to misconfigured iFrame sandbox attributes (`allow-scripts` and `allow-same-origin` are hardcoded as true), the malicious JavaScript executes unhindered in the context of the victim's browser.
8.  **Impact**: The executed script performs actions such as exfiltrating the victim's session tokens from local storage (leading to session hijacking) or, if the victim is an administrator, potentially triggering a remote code execution vulnerability on the server.

## Impact

The vulnerability allows any authenticated user to create a weaponized chat that can be persistently stored and shared, enabling attacks against other users. Low-privilege users face a risk of session takeover if their session tokens are exfiltrated from local storage to an attacker-controlled server. For administrators, the vulnerability introduces a pathway to exposing the server to Remote Code Execution (RCE), building upon chains described in related vulnerabilities like GHSA-w7xj-8fx7-wfch. Successful exploitation grants attackers unauthorized access to user sessions and potentially server control, leading to data breaches, unauthorized modifications, or further system compromise.

## Recommendation

*   Patch CVE-2026-26193 on all Open WebUI instances immediately by updating to a version greater than 0.6.43.
*   Review web application logs and WAF/API gateway logs for unusual POST requests to chat saving endpoints (`/api/chat/`) that contain the 'embeds' keyword in the request body, which could indicate exploitation attempts of the vulnerability described in this brief.
