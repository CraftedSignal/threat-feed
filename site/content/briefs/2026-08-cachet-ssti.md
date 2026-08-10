---
title: Remote Code Execution via SSTI in Cachet
slug: 2026-08-cachet-ssti
description: Cachet versions 2.4.1 and earlier are vulnerable to server-side template injection in incident template rendering, allowing authenticated attackers to execute arbitrary system commands.
date: "2026-08-10T21:36:39Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Cachet
products:
  - Cachet (<= 2.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Cachet through 2.4.1 contains a server-side template injection vulnerability in incident template rendering that allows authenticated users to execute arbitrary PHP code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can create malicious incident templates with Blade directives or Twig filters that execute system commands when incidents are created, achieving remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-69118
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69118
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Cachet instances to a version > 2.4.1.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-69118 patch availability
  mitigation_plan:
    - priority: immediate
      action: Audit incident template permissions and contents for malicious syntax.
      owner: Security Operations
      addresses: CVE-2026-69118
      evidence: Source documentation of SSTI vector
---

Cachet versions 2.4.1 and earlier contain a server-side template injection (SSTI) vulnerability during the processing of incident templates. The application fails to properly sanitize user-supplied input when rendering these templates, which rely on the Blade templating engine or Twig filters. An authenticated user with sufficient permissions to create or modify incident templates can inject malicious syntax that is subsequently executed by the application's template engine. This allows an attacker to execute arbitrary PHP code under the context of the web server process, potentially leading to a full system compromise. The vulnerability is critical for organizations that allow users with incident management roles to modify global or incident-specific templates.

## Impact

Successful exploitation allows for arbitrary remote code execution on the server hosting the Cachet instance. This can lead to complete loss of confidentiality, integrity, and availability of the application and the underlying server. Impact includes potential unauthorized data access, lateral movement within the network, and the deployment of persistent backdoors.

## Recommendation

- Upgrade Cachet instances to the latest available patched version to remediate the vulnerability.
- Review all incident templates for unauthorized modifications, specifically looking for Blade or Twig directives, such as {{ }} or {!! !!}, that contain non-standard PHP functions.
- Restrict the ability to create and modify incident templates to highly trusted administrative accounts only.
- Implement web application firewall (WAF) rules to inspect POST requests directed at template management endpoints for common template injection characters and strings.
