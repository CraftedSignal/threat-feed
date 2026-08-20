---
title: Multiple Vulnerabilities in n8n Workflow Automation
slug: 2026-08-n8n-vulnerabilities
description: Multiple vulnerabilities in n8n allow a remote, authenticated attacker to achieve remote code execution, bypass security controls, perform SSRF, and manipulate sensitive data.
date: "2026-08-20T13:11:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - n8n
  - vulnerability
  - workflow-automation
vendors:
  - n8n GmbH
products:
  - n8n
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A remote, authenticated attacker can exploit multiple vulnerabilities to execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated attacker can manipulate data and disclose information.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2936
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review n8n authentication logs for anomalous account behavior.
      owner: SOC
      due: 24h
      evidence: Source indicates vulnerabilities require an authenticated attacker.
  mitigation_plan:
    - priority: immediate
      action: Patch n8n instance to the latest version.
      owner: IT Operations
      addresses: n8n vulnerabilities
      evidence: BSI vulnerability disclosure.
---

The BSI has reported multiple vulnerabilities affecting n8n, a workflow automation platform. These vulnerabilities can be exploited by a remote, authenticated attacker to gain unauthorized control over the instance. The potential impact of successful exploitation includes arbitrary code execution (RCE), the circumvention of security controls, Server-Side Request Forgery (SSRF), unauthorized information disclosure, and data manipulation. The severity of these issues is classified as high, as they provide an attacker who has achieved initial authentication with the ability to escalate privileges or move laterally within the infrastructure by leveraging the automation capabilities inherent to the n8n application. Defenders should prioritize auditing authenticated user activity and inspecting application-level outgoing network traffic.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to compromise the integrity and confidentiality of the n8n instance and any integrated services. This includes access to credentials, workflow data, and the ability to execute system commands on the host server. The impact is significant for organizations relying on n8n for critical business processes, as an attacker could potentially bridge the gap between the automation platform and internal backend systems.

## Recommendation

- Monitor the n8n application environment for unexpected outbound network connections, specifically those originating from the application process to sensitive internal infrastructure.
- Review authenticated user logs for anomalous API activity or the creation of workflows that execute system shell commands.
- Audit all active user accounts and API keys within n8n to ensure only authorized personnel have access.
- Apply the latest vendor security patches immediately upon availability to remediate these vulnerabilities.
