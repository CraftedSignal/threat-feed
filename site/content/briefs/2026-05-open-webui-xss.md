---
title: Open WebUI Stored XSS Vulnerability in Excel File Preview
slug: 2026-05-open-webui-xss
description: Open WebUI is vulnerable to stored XSS when previewing Excel files; a crafted XLSX file can embed an XSS payload into the generated HTML, leading to arbitrary code execution when the file is previewed, allowing attackers to create weaponized chats and potentially compromise user sessions or gain RCE.
date: "2026-05-09T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - xss
  - stored-xss
  - open-webui
vendors:
  - Open WebUI
products:
  - open-webui (<= 0.7.2)
references:
  - https://github.com/advisories/GHSA-jwf8-pv5p-vhmc
rules:
  - title: Detects CVE-2026-44549 Exploitation — Open WebUI Excel File XSS
    description: Detects CVE-2026-44549 exploitation — attempts to exploit the Open WebUI Excel file XSS vulnerability by searching for script tags or onerror attributes in the server response.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
  - title: Detects CVE-2026-44549 Exploitation — Open WebUI Excel File XSS with alert
    description: Detects CVE-2026-44549 exploitation — attempts to trigger an alert box in Open WebUI by exploiting the Excel file XSS vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI is susceptible to a stored cross-site scripting (XSS) vulnerability due to unsafe handling of Excel file previews. Specifically, a maliciously crafted XLSX file can inject arbitrary HTML and JavaScript code into the generated preview, which is then executed in the user's browser. This is due to the `sheet_to_html` function from the sheetjs library not sanitizing the HTML output. An attacker can exploit this vulnerability by crafting a weaponized chat with a malicious XLSX attachment, which when previewed by a victim, triggers the XSS payload. Versions of Open WebUI up to and including 0.7.2 are affected. Successful exploitation could lead to session hijacking and potentially remote code execution on the server.

## Attack Chain

1. An attacker crafts a malicious XLSX file containing an XSS payload within a cell using a tool like xlsxwriter.
2. The attacker uploads this malicious XLSX file as an attachment in Open WebUI.
3. The attacker shares the chat or sends the file directly to the victim.
4. The victim opens the chat containing the malicious attachment.
5. The victim clicks on the attachment to open the file modal.
6. The victim selects the preview tab in the file modal, triggering the XLSX to HTML conversion.
7. The vulnerable `sheet_to_html` function processes the XLSX file and embeds the malicious XSS payload into the generated HTML.
8. The generated HTML, now containing the XSS payload, is injected into the DOM unsanitized, causing the payload to execute. The payload can then perform actions such as stealing session cookies or executing arbitrary JavaScript code.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of the victim's browser within the Open WebUI application. This can lead to session hijacking, where the attacker gains control of the victim's account. Furthermore, administrators are at risk of remote code execution (RCE) on the server by chaining this vulnerability with other vulnerabilities in Open WebUI. The impact affects all users of Open WebUI up to version 0.7.2 who interact with shared files.

## Recommendation

*   Apply the vendor-provided patch or upgrade to a version of Open WebUI greater than 0.7.2.
*   Deploy the following Sigma rule to detect attempts to exploit CVE-2026-44549 by detecting malicious script tags in the response HTML.
*   Implement input sanitization using DOMPurify or a similar library to sanitize the HTML generated from XLSX files before rendering it in the DOM, as recommended in the advisory.
*   Educate users about the risks of opening attachments from untrusted sources, even within trusted applications.
