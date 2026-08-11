---
title: Remote Code Execution in PapersGPT for Zotero
slug: 2026-08-papersgpt-rce
description: PapersGPT for Zotero 0.6.1 is vulnerable to remote code execution due to unsanitized LLM responses being passed to window.eval(), allowing full system access.
date: "2026-08-11T21:49:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - PapersGPT
products:
  - PapersGPT for Zotero (0.6.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows attackers to execute arbitrary JavaScript by returning malicious code from an LLM endpoint that is passed unsanitized to window.eval() in views.ts.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can exploit this through prompt injection in PDFs, MITM interception of API requests, or a malicious custom LLM endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-73032
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73032
---

PapersGPT for Zotero version 0.6.1 contains a high-severity remote code execution (RCE) vulnerability that stems from the improper handling of responses from large language model (LLM) endpoints. Specifically, the application's 'views.ts' component passes unsanitized content returned by LLMs directly into the 'window.eval()' function. This insecure implementation allows an attacker to execute arbitrary JavaScript in the context of Zotero's chrome-privileged environment. By leveraging techniques such as PDF-based prompt injection, man-in-the-middle (MITM) interception of API requests, or configuring the extension to use a malicious custom LLM endpoint, an attacker can escape the application sandbox. Successful exploitation grants the attacker extensive capabilities on the host system, including unauthorized file system read/write operations, process execution, and access to all sensitive data stored within the Zotero application. Given that the extension operates with high-level privileges within the browser or desktop shell, this vulnerability poses a significant risk to user data and system integrity.

## Attack Chain

1. Attacker identifies a target user utilizing the PapersGPT for Zotero extension (version 0.6.1).
2. Attacker sets up a malicious LLM endpoint or performs MITM interception on the extension's network traffic.
3. Attacker triggers an interaction within the Zotero interface that prompts a request to the LLM endpoint (e.g., summarizing a PDF).
4. The malicious LLM endpoint returns a crafted payload containing arbitrary JavaScript code wrapped in a response expected by the extension.
5. The extension receives the response and passes the unsanitized payload to 'window.eval()' inside 'views.ts'.
6. The JavaScript payload executes within the chrome-privileged context of the Zotero application.
7. The attacker leverages the privileged context to execute system commands or interact with the local file system.
8. Full system impact is achieved, including data exfiltration and persistent local code execution.

## Impact

Successful exploitation of this vulnerability results in full compromise of the local Zotero environment and the underlying host system. An attacker can access all stored research data, read or write arbitrary files, and execute arbitrary processes with the permissions of the user running Zotero. Because Zotero runs as a desktop application, this effectively bypasses standard web-extension isolation, potentially impacting all research-heavy environments where this tool is deployed.

## Recommendation

1. Immediately update or remove the PapersGPT for Zotero extension if a patch is available from the vendor.
2. For enterprise environments, use endpoint management tools to block the extension 'PapersGPT' globally until version 0.6.2 or later is verified as installed.
3. Audit network traffic originating from Zotero to identify connections to unauthorized or anomalous LLM endpoints.
4. Restrict Zotero's network access via host-based firewalls to strictly defined, legitimate LLM API domains to mitigate the impact of MITM-based exploitation.
