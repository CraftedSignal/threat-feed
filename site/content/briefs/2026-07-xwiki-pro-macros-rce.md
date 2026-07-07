---
title: XWiki Pro Macros Remote Code Execution via Excerpt-Include Macro (CVE-2026-44179)
slug: 2026-07-xwiki-pro-macros-rce
description: A critical vulnerability, CVE-2026-44179, exists in XWiki Pro Macros versions before 1.14.5, allowing remote code execution for any user with page editing rights due to improper escaping of page titles and content processed by the excerpt-include macro, leading to XWiki syntax injection and full compromise of the XWiki installation.
date: "2026-07-03T11:06:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xwiki
  - rce
  - vulnerability
  - java
  - web-application
vendors:
  - XWiki
products:
  - xwiki-pro-macros (>= 1.13, < 1.14.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The excerpt-include macro does not properly escape the title of the included page and executes the content of the excerpt with the macro's rights. Therefore, it is vulnerable to XWiki syntax injection via the included page's title and content, allowing remote code execution for any user who can edit a page.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w56x-9778-rppx
---

A critical vulnerability, tracked as CVE-2026-44179, affects XWiki Pro Macros versions 1.13 through 1.14.4. This flaw enables remote code execution (RCE) on affected XWiki installations. The vulnerability stems from the `excerpt-include` macro's failure to properly escape the title of an included page and its execution of excerpt content with elevated rights. This allows for XWiki syntax injection, where an attacker with basic page editing privileges can embed malicious Groovy code within a page's title or content. When this page is subsequently rendered or included by the `excerpt-include` macro, the embedded code is executed, providing the attacker with full control over the XWiki instance. This impacts the confidentiality, integrity, and availability of the entire XWiki system.

## Attack Chain

1.  An attacker gains or already possesses valid credentials to an XWiki instance with page editing permissions, even without specific script or programming rights.
2.  The attacker creates a new XWiki page, for example, named "Exploit", using the standard page creation interface.
3.  The attacker then edits the "Exploit" page and maliciously modifies its title to include an XWiki Groovy Remote Code Execution (RCE) payload, such as `{{async}}{{groovy}}println("Malicious Code"){{/groovy}}{{/async}}`.
4.  The attacker embeds the vulnerable `excerpt-include` macro within the content of the same "Exploit" page, configured to include itself (e.g., `{{excerpt-include 0="Exploit.WebHome"}}{{/excerpt-include}}`).
5.  Concurrently, the attacker injects another Groovy RCE payload directly into an `{{excerpt}}` block within the page's content, which will also be processed by the macro.
6.  Upon saving or rendering the "Exploit" page, the XWiki engine processes the `excerpt-include` macro, which, due to improper escaping, executes the embedded Groovy code from the page's title and content.
7.  The embedded Groovy code runs with the `excerpt-include` macro's rights, leading to successful Remote Code Execution on the underlying XWiki server.

## Impact

The successful exploitation of CVE-2026-44179 leads to remote code execution on the XWiki server. This allows an attacker to execute arbitrary commands, compromise the integrity of the XWiki data, exfiltrate sensitive information, or disrupt the availability of the service. While no specific victim count is provided, the vulnerability affects all XWiki installations using the `xwiki-pro-macros` package within the vulnerable version range, posing a significant risk to any organization relying on XWiki for content management and collaboration.

## Recommendation

*   Prioritize patching XWiki Pro Macros to version 1.14.5 or later to remediate CVE-2026-44179 immediately.
*   Review XWiki audit logs for any unusual page title modifications or new page creations containing suspicious syntax like `{{async}}{{groovy}}` or `println(`.
*   Implement strong access controls for XWiki page editing, adhering to the principle of least privilege, even though this vulnerability bypasses typical script execution restrictions.
