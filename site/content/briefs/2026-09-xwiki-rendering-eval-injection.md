---
title: Eval Injection in XWiki Rendering XML
slug: 2026-09-xwiki-rendering-eval-injection
description: An evaluation injection vulnerability in xwiki-rendering-xml allows authenticated users to achieve remote code execution by injecting script macros into HTML macro output.
date: "2026-09-18T19:48:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:xwiki:xwiki_rendering:*:*:*:*:*:*:*:*
tags:
  - injection
  - rce
  - web-vulnerability
vendors:
  - XWiki
products:
  - xwiki-rendering-xml (< 14.10.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker with permissions to edit documents can inject and execute arbitrary script macros, including Groovy and Python, which run with programming rights.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker with permissions to edit documents can inject and execute arbitrary script macros, including Groovy and Python, which run with programming rights.
    confidence_band: high
cves:
  - id: CVE-2025-53837
    cvss: 9.9
references:
  - https://github.com/advisories/GHSA-26vp-8gxg-v4pg
  - https://nvd.nist.gov/vuln/detail/CVE-2025-53837
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade xwiki-rendering-xml to 14.10.2 or 15.0 RC1
      owner: IT Operations
      due: 48h
      evidence: 'Source states: This has been patched in XWiki 14.10.2 and 15.0 RC1.'
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2025-53837
      owner: IT Operations
      addresses: CVE-2025-53837
      evidence: Source advisory
---

The xwiki-rendering-xml component is vulnerable to an evaluation injection issue (CVE-2025-53837) due to insufficient escaping of rendering output when used within HTML macros. An attacker with standard document editing permissions, such as the ability to edit their own user profile or other wiki documents, can craft malicious input that prematurely closes the HTML macro block. This enables the injection of arbitrary script macros, including Groovy and Python. Because these macros are executed with programming rights, the impact includes full, unrestricted read and write access to all wiki content and potential remote code execution on the underlying server. The vulnerability affects XWiki versions prior to 14.10.2 and 15.0 RC1. Defenders should prioritize patching to the identified versions to prevent unauthorized script execution via the rendering pipeline.

## Impact

Successful exploitation grants an attacker full control over the wiki installation, including data exfiltration and administrative control via script execution. The vulnerability is highly impactful due to the broad nature of programming rights in XWiki, which effectively elevates standard user document-editing access to full system command execution capabilities within the application context.

## Recommendation

- Upgrade XWiki installations utilizing xwiki-rendering-xml to version 14.10.2 or 15.0 RC1 immediately to remediate CVE-2025-53837.
- Review and audit user-created documents and profile pages for suspicious object additions, specifically looking for those utilizing the 'XWiki.UIExtensionClass'.
- Restrict document editing permissions to trusted users to reduce the potential attack surface while the upgrade is pending.
