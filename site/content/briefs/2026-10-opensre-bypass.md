---
title: OpenSRE Approval Gate Bypass Vulnerability
slug: 2026-10-opensre-bypass
description: OpenSRE versions through 0.1.2026.10.19 are vulnerable to an approval gate bypass that enables arbitrary command execution via manipulated alert or messaging inputs.
date: "2026-10-20T02:32:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:opensre:opensre:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - opensre
  - cve-2026-109444
vendors:
  - OpenSRE
products:
  - OpenSRE (<= 0.1.2026.10.19)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can inject instructions into alerts or Slack messages triaged by the agent to run commands on the host.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials In Files'
    evidence: Attackers can exfiltrate LLM, Slack and cloud credentials.
    confidence_band: high
cves:
  - id: CVE-2026-109444
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109444
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenSRE to version 0.1.2026.10.20 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109444 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenSRE software
      owner: IT Operations
      addresses: CVE-2026-109444
      evidence: NVD advisory for CVE-2026-109444
---

OpenSRE versions through 0.1.2026.10.19 contain a critical vulnerability in the headless presenter component. The application’s execution_allowed() function incorrectly returns a constant value of True, effectively bypassing the security controls designed to gate automated command execution. This flaw allows an attacker to inject arbitrary system commands through inputs typically processed by the agent, such as alerts or Slack messages. If successful, the attacker can execute commands on the underlying host, facilitating unauthorized actions such as the exfiltration of sensitive LLM configuration, Slack tokens, and cloud environment credentials. This vulnerability is particularly impactful for organizations relying on automated remediation or incident response workflows within OpenSRE.

## Impact

Successful exploitation allows for full command execution on the host machine running the OpenSRE agent. This access exposes the organization to significant risk, including the compromise of cloud infrastructure, theft of API and platform-specific credentials, and potential pivoting into internal networks. The vulnerability affects all deployments of OpenSRE through version 0.1.2026.10.19.

## Recommendation

Prioritized actions for detection engineering and security operations teams:

- Upgrade all instances of OpenSRE to a version beyond 0.1.2026.10.19 immediately.
- Audit logs for the execution of shell_run or equivalent command-line functions originating from the OpenSRE process context.
- Restrict the permissions of the user account running the OpenSRE agent to the principle of least privilege, specifically limiting access to environment variables, credentials, and cloud metadata services.
