---
title: Open WebUI Stored XSS Vulnerability (CVE-2026-45303)
slug: 2026-05-open-webui-xss
description: Open WebUI versions before 0.6.5 are vulnerable to stored cross-site scripting (XSS) due to improper sanitization of HTML content displayed within an iFrame, potentially allowing an attacker to inject malicious scripts into chat messages and steal sensitive information like user tokens with some user interaction.
date: "2026-05-14T20:17:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - stored-xss
  - open-webui
vendors:
  - pip
products:
  - open-webui (< 0.6.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-4vrc-m9ch-6m3r
  - CVE-2026-45303
iocs:
  - type: url
    value: https://www.attacker.local/?
ioc_counts:
  url: 1
rules:
  - title: Detect Open WebUI XSS Payload via Attacker Domain
    description: Detects XSS attempts in Open WebUI by identifying network connections to the attacker's domain after a chat message is rendered, indicating potential token theft.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect Open WebUI XSS Payload via Script Tag in Chat Message
    description: Detects XSS attempts in Open WebUI by identifying script tags in chat messages indicative of potential XSS payload injection.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions before 0.6.5 are susceptible to a stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-45303. This flaw arises from insufficient sanitization of HTML content within chat messages. The frontend provides a function to visualize HTML content of a current chat. The content is embedded in an iFrame with the following permissive sandbox directive: `sandbox="allow-scripts allow-forms allow-same-origin"`. This iFrame configuration allows scripts to execute and access the parent's data, effectively negating the intended security benefits of the sandbox. The vulnerability was discovered during a penetration test and is believed to stem from a core issue within Open WebUI's code. Successful exploitation could lead to the theft of sensitive user data, such as tokens.

## Attack Chain

1. An attacker crafts a malicious HTML message containing a JavaScript payload designed to steal user tokens.
2. The attacker injects the malicious HTML message into a chat within Open WebUI, either by directly entering it or via chat sharing functionality.
3. The victim views the chat containing the attacker's message.
4. Open WebUI renders the message and embeds the attacker's HTML content, including the malicious JavaScript, within an iFrame.
5. The iFrame's sandbox configuration allows the JavaScript code to execute.
6. The attacker's JavaScript code accesses the victim's local storage, retrieves the user's token.
7. The JavaScript sends the stolen token to an attacker-controlled domain, such as `https://www.attacker.local/?`.
8. The attacker receives the stolen token and can use it to impersonate the victim.

## Impact

This vulnerability is fundamentally a self-XSS, but the impact can be extended under certain conditions. While the exploitability is considered low due to the high attack complexity, successful exploitation can lead to sensitive information disclosure, specifically the theft of user tokens. A successful attack allows the attacker to impersonate the victim and potentially gain unauthorized access to the victim's account and data. Attack vectors include tricking users into entering malicious input, chat sharing, uploading malicious files, and importing malicious chat conversations.

## Recommendation

*   Restrict the iFrame sandbox to prevent scripts from executing with access to the parent’s data, mitigating the XSS vulnerability.
*   Deploy the Sigma rule `Detect Open WebUI XSS Payload via Attacker Domain` to identify instances where the attacker's domain is present in network connections originating from Open WebUI.
*   Upgrade Open WebUI to version 0.6.5 or later to patch CVE-2026-45303.
