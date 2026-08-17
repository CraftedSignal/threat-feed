---
title: Cross-Site Scripting Vulnerability in Legora via Mermaid Blocks
slug: 2026-08-legora-xss
description: Legora versions prior to 2026-08-14 are vulnerable to cross-site scripting via insecure front-matter parsing in Mermaid diagram blocks, allowing arbitrary JavaScript execution and potential session token theft.
date: "2026-08-17T20:50:49Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Legora
products:
  - Legora
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Legora before 2026-08-14 contains a cross-site scripting vulnerability that allows attackers to achieve arbitrary JavaScript execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: causing the front-matter parser to invoke eval() before any SVG sanitization occurs.
    confidence_band: high
cves:
  - id: CVE-2026-74234
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74234
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Legora to 2026-08-14 or later
      owner: IT Operations
      due: 48h
      evidence: Legora before 2026-08-14 contains a cross-site scripting vulnerability
  mitigation_plan:
    - priority: immediate
      action: Review and restrict browser storage access for add-ins
      owner: IT Operations
      addresses: CVE-2026-74234
      evidence: elevated impact on Word and Outlook add-in surfaces where bearer session tokens are persisted in localStorage
---

Legora versions released prior to 2026-08-14 contain a critical cross-site scripting (XSS) vulnerability related to the handling of Mermaid diagram blocks. The application utilizes a front-matter parser that improperly invokes the eval() function on diagram content prefixed with JavaScript front-matter directives before any SVG sanitization is performed. This flaw allows attackers to execute arbitrary JavaScript within the context of the victim's browser session. 

The impact is particularly severe when Legora is deployed as a Word or Outlook add-in, where the browser session shares the same origin or local storage access as the host application. In these environments, the execution of unauthorized scripts enables the exfiltration of sensitive bearer session tokens persisted in localStorage. Defenders should prioritize patching Legora to version 2026-08-14 or later to remediate the unsafe parsing logic.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript in the victim's browser, potentially leading to unauthorized access to user data, session hijacking via token theft in Word and Outlook environments, and impersonation of the legitimate user.

## Recommendation

- Upgrade all instances of Legora to version 2026-08-14 or later immediately.
- Review browser-based access logs for web-based instances of Legora to identify requests containing atypical Mermaid syntax or front-matter directives.
- Implement Content Security Policy (CSP) headers that restrict the execution of inline scripts and disallow the use of eval() if the application architecture permits.
