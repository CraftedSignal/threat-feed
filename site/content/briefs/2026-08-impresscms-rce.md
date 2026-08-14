---
title: Authenticated RCE in ImpressCMS Custom Tag Module
slug: 2026-08-impresscms-rce
description: ImpressCMS contains an authenticated remote code execution vulnerability (CVE-2026-73679) in the custom tag module, allowing administrators to execute arbitrary PHP code via improperly sanitized input.
date: "2026-08-14T20:13:13Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - ImpressCMS
products:
  - ImpressCMS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The application decodes HTML-encoded content via undoHtmlSpecialChars() before passing it to eval() in the renderWithPhp() method.
    confidence_band: high
cves:
  - id: CVE-2026-73679
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73679
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review and audit all active custom tags with PHP type enabled.
      owner: IT Operations
      due: 24h
      evidence: Source document identifies the custom tag module as the vector.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to patched version of ImpressCMS.
      owner: IT Operations
      addresses: CVE-2026-73679
      evidence: NVD vulnerability disclosure.
---

ImpressCMS is susceptible to a remote code execution vulnerability (CVE-2026-73679) within its custom tag module. The vulnerability allows an authenticated administrator to inject arbitrary PHP code by creating a custom tag with the PHP type enabled. The application's renderWithPhp() method processes these tags by calling the undoHtmlSpecialChars() function, which decodes HTML-encoded content before passing it directly to the PHP eval() function. This process bypasses the HTML Purifier sanitization layer that is intended to secure user-provided content. Because these tags are processed through the system's preload event mechanism, the injected payload executes automatically on every frontend page load, providing the attacker with persistent command execution within the application context.

## Impact

Successful exploitation of this vulnerability allows an authenticated administrative user to achieve full code execution on the underlying web server. This can lead to total system compromise, including unauthorized data access, modification of site content, and potential lateral movement within the hosting infrastructure.

## Recommendation

1. Patch ImpressCMS to the latest version as soon as the vendor releases a fix for CVE-2026-73679.
2. Audit current administrator user accounts for signs of unauthorized access or activity.
3. Review the custom tag module configuration for any tags with the 'PHP' type enabled that were not explicitly created by authorized personnel.
4. Deploy web application firewall (WAF) rules to monitor and block requests that attempt to pass malicious PHP payloads into the custom tag creation or modification endpoints.
