---
title: n8n DOM-Based XSS via Unsandboxed iframe srcdoc in HTML Preview
slug: 2026-07-n8n-dom-based-xss
description: A DOM-Based Cross-Site Scripting (XSS) vulnerability in n8n allows an attacker to inject scripts into the HTML preview through an unsandboxed iframe srcdoc, enabling the injected script to run with the same origin as the editor; if a victim opens this compromised preview, the script can call authenticated APIs using their session, allowing an account with 'global:member' privileges to exploit this to gain unauthorized access or perform actions.
date: "2026-07-22T18:03:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - n8n
  - xss
  - vulnerability
  - web-application
vendors:
  - n8n GmbH
products:
  - 'n8n (Vulnerable: < 1.123.64)'
  - 'n8n (Vulnerable: >= 2.30.0, < 2.30.1)'
  - 'n8n (Vulnerable: >= 2.0.0-rc.0, < 2.29.8)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A DOM-Based Cross-Site Scripting (XSS) vulnerability in n8n allows an attacker to inject scripts into the HTML preview...This enables the injected script to run...the script can call authenticated APIs with their session.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: If a victim opens this compromised preview, the script can call authenticated APIs with their session.
    confidence_band: high
cves:
  - id: CVE-2026-65597
references:
  - https://github.com/advisories/GHSA-p3rg-hrf9-w9gj
---

A critical DOM-Based Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-65597, has been discovered in the n8n workflow automation platform. This flaw allows an attacker to inject malicious scripts into the HTML preview feature, which renders content within an `iframe srcdoc` without proper sandboxing. Consequently, injected scripts execute with the same origin as the n8n editor, bypassing client-side sanitization. Exploitation occurs when a victim, possessing `global:member` privileges, opens a crafted HTML preview containing the malicious payload. The executing script can then leverage the victim's authenticated session to interact with n8n's internal APIs, potentially leading to unauthorized data access, privilege escalation, or arbitrary actions within the platform. This vulnerability affects multiple n8n versions prior to fixed releases, including < 1.123.64, >= 2.30.0 and < 2.30.1, and >= 2.0.0-rc.0 and < 2.29.8.

## Attack Chain

1. An attacker with appropriate access crafts malicious input containing an XSS payload, potentially within an HTML node or via externally-controlled input rendered by n8n.
2. The n8n application processes this malicious input within a workflow execution.
3. n8n renders the output containing the attacker-controlled HTML and JavaScript into an `iframe srcdoc` for preview purposes.
4. Due to the absence of the `sandbox` attribute on the iframe, the injected script executes in the context of the n8n editor's origin.
5. A legitimate n8n user, possessing `global:member` privileges, interacts with the platform and opens the compromised HTML preview.
6. The attacker's injected JavaScript executes within the victim's browser, leveraging their authenticated session.
7. The script makes unauthorized calls to n8n's authenticated APIs, using the victim's session cookies or tokens.
8. The attacker achieves their objective, such as unauthorized data access, modification of workflows, or privilege escalation within the n8n instance.

## Impact

Successful exploitation of CVE-2026-65597 could allow attackers to gain unauthorized control over a victim's n8n session. By injecting malicious scripts, an attacker can perform actions on behalf of the victim, such as accessing sensitive workflow data, modifying existing workflows, or creating new ones, potentially leading to disruption of business processes or further compromise of integrated systems. While specific victim counts are not disclosed, any organization utilizing vulnerable n8n versions, especially those allowing untrusted users or exposing workflows that process external inputs, is at risk. The primary impact is unauthorized API calls and actions taken with the victim's privileges within the n8n environment.

## Recommendation

- Immediately upgrade n8n to versions 1.123.64, 2.29.8, 2.30.1, or later to patch CVE-2026-65597 in the affected products.
- Implement network-level restrictions to limit access to the n8n instance to only fully trusted users and IP ranges.
- Configure the `N8N_CONTENT_SECURITY_POLICY` environment variable with a robust policy that blocks inline scripts to mitigate client-side script execution.
- Review and secure n8n workflows that process externally-controlled input, ensuring they do not render into the HTML node or binary HTML preview if handling untrusted data.
