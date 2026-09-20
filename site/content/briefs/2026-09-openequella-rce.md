---
title: Remote Code Execution in openEQUELLA via FreeMarker Template Injection
slug: 2026-09-openequella-rce
description: Authenticated users can achieve remote code execution in openEQUELLA versions prior to 2026.1.0 by leveraging an unsandboxed FreeMarker configuration to execute arbitrary system commands.
date: "2026-09-20T12:21:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apereo:openequella:*:*:*:*:*:*:*:*
vendors:
  - Apereo Foundation
products:
  - openEQUELLA (< 2026.1.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated attackers can inject malicious template expressions ... to instantiate dangerous classes like freemarker.template.utility.Execute and invoke Runtime.exec for arbitrary command execution.
    confidence_band: high
cves:
  - id: CVE-2026-94109
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94109
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade openEQUELLA to version 2026.1.0 or later
      owner: IT Operations
      addresses: CVE-2026-94109
      evidence: NVD vulnerability report
---

Apereo Foundation's openEQUELLA versions prior to 2026.1.0 contain a critical remote code execution (RCE) vulnerability stemming from the insecure configuration of the FreeMarker template engine. The application fails to properly sandbox the TemplateClassResolver during template compilation. This allows authenticated users with access to administrative or content-management interfaces - such as the creation of collection summaries, dashboard portlets, or MIME templates - to inject malicious FreeMarker expressions. By exploiting this, an attacker can instantiate sensitive Java classes, specifically `freemarker.template.utility.Execute`, to invoke `Runtime.exec` on the underlying host operating system. This vulnerability allows for full system command execution within the context of the service account running the openEQUELLA application. Given the nature of the application as a digital repository, defenders should focus on monitoring administrative actions and input fields that allow for template or script-like data entry.

## Impact

The vulnerability allows an authenticated attacker to execute arbitrary code with the privileges of the application server. This could lead to a full system compromise, exfiltration of sensitive repository data, or the deployment of persistent malware. Affected sectors include higher education and research institutions that rely on openEQUELLA for digital asset management.

## Recommendation

* Upgrade all instances of openEQUELLA to version 2026.1.0 or later to apply the necessary security patches for FreeMarker configuration.
* Audit application access logs for unusual administrative activity, particularly involving the creation or modification of collection summaries, dashboard portlets, or MIME templates.
* Limit the creation of content templates and dashboard portlets to highly trusted administrative roles to minimize the attack surface until the patch is applied.
