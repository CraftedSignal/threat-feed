---
title: OS Command Injection in Lenovo XClarity Orchestrator
slug: 2026-08-lenovo-lxco-rce
description: Lenovo XClarity Orchestrator (LXCO) versions prior to 2.2.0 contain an OS command injection vulnerability (CVE-2026-16793) allowing authenticated attackers to execute arbitrary commands with high privileges.
date: "2026-08-04T22:02:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - rce
  - injection
  - enterprise-management
vendors:
  - Lenovo
products:
  - XClarity Orchestrator
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An improper neutralization of special elements used in an operating system command vulnerability was reported in Lenovo XClarity Orchestrator (LXCO) 2.2.0 that could allow an authenticated attacker to execute arbitrary operating system commands as a privileged user under a specific circumstance.
    confidence_band: high
cves:
  - id: CVE-2026-16793
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16793
  - https://support.lenovo.com/my/en/solutions/ht509976-lenovo-xclarity-orchestrator
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Lenovo XClarity Orchestrator to 2.2.0 or later
      owner: IT Operations
      due: 72h
      evidence: Vendor advisory indicates 2.2.0 remediates the vulnerability
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the LXCO web management interface
      owner: IT Operations
      addresses: CVE-2026-16793
      evidence: Mitigates risk of unauthorized exploitation from external networks
---

Lenovo has identified a critical OS command injection vulnerability, tracked as CVE-2026-16793, affecting Lenovo XClarity Orchestrator (LXCO) versions earlier than 2.2.0. This vulnerability, categorized under CWE-78 (Improper Neutralization of Special Elements used in an OS Command), occurs due to insufficient input validation of user-supplied data. An attacker who has already authenticated to the LXCO management interface can leverage this flaw to execute arbitrary operating system commands with elevated privileges. Given the nature of LXCO as a management tool for IT infrastructure, this vulnerability presents a significant risk, potentially leading to full system compromise of the orchestrator, which could then be used as a pivot point for further lateral movement within the data center environment.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to achieve code execution as a privileged user on the LXCO instance. This grants the attacker complete control over the appliance, enabling data exfiltration, service disruption, and the ability to manipulate the managed infrastructure overseen by the orchestrator.

## Recommendation

Prioritized actions for security and IT teams:
- Upgrade all instances of Lenovo XClarity Orchestrator to version 2.2.0 or later to remediate CVE-2026-16793.
- Implement strict access control for the LXCO management interface, limiting access to a subset of trusted administrative IP addresses to reduce the likelihood of unauthorized authentication.
- Review audit logs for the LXCO management web interface for suspicious commands or anomalous parameter values following an authenticated session.
