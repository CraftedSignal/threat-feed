---
title: GitHub Copilot and Visual Studio Code Information Disclosure Vulnerability
slug: 2026-07-github-copilot-vs-code-info-disclosure
description: A vulnerability, identified as CVE-2026-47282, in GitHub Copilot and Visual Studio Code allows an unauthorized attacker to disclose sensitive information over a network due to insufficiently protected credentials.
date: "2026-07-14T17:11:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - information-disclosure
  - vulnerability
  - development-tools
vendors:
  - GitHub
  - Microsoft
products:
  - GitHub Copilot
  - Visual Studio Code
affected_os:
  - Windows
  - Linux
  - macOS
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47282
---

Microsoft has disclosed CVE-2026-47282, an information disclosure vulnerability affecting GitHub Copilot and Visual Studio Code. This vulnerability stems from insufficiently protected credentials within these popular development tools, which could enable an unauthorized attacker to disclose sensitive information over a network. While the advisory does not detail specific exploitation methods or observed in-the-wild attacks, the presence of such a flaw in widely used developer environments poses a risk. Developers often handle sensitive data, API keys, and source code, making any information leakage vector a concern. Defenders should prioritize patching and monitoring for unusual network activity originating from developer workstations.

## Impact

Successful exploitation of CVE-2026-47282 could lead to the unauthorized disclosure of sensitive information. Depending on the credentials or data exposed, this could include developer API keys, access tokens, internal network details, or source code. While the immediate impact is information leakage rather than direct system compromise, this disclosed information could serve as a stepping stone for further, more severe attacks, including unauthorized access to internal systems, data repositories, or cloud environments. Organizations with development teams utilizing GitHub Copilot and Visual Studio Code are particularly at risk.

## Recommendation

* Patch CVE-2026-47282 immediately by updating GitHub Copilot and Visual Studio Code to the latest secure versions as advised by Microsoft.
* Implement network monitoring solutions to detect unusual outbound network connections or credential transfers originating from developer workstations that could indicate exploitation of the vulnerability.
* Ensure developers are following secure coding practices and credential management policies to minimize the exposure of sensitive information in their development environments.
