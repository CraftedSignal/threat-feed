---
title: Unauthenticated OS Command Injection in NUMail
slug: 2026-08-numail-rce
description: NUMail contains an unauthenticated OS command injection vulnerability allowing remote attackers to execute arbitrary system-level commands on affected servers.
date: "2026-08-28T07:11:33Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - remote-code-execution
  - vulnerability
  - web-application
vendors:
  - Green-Computing
products:
  - NUMail
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated remote attackers can inject arbitrary OS commands and execute them on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Unauthenticated remote attackers can inject arbitrary OS commands and execute them on the server.
    confidence_band: high
cves:
  - id: CVE-2026-82082
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82082
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory NUMail deployments
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82082
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to NUMail services via firewall
      owner: IT Operations
      addresses: CVE-2026-82082
      evidence: Unauthenticated remote exploitation potential
---

NUMail, developed by Green-Computing, is affected by an OS command injection vulnerability identified as CVE-2026-82082. This vulnerability allows an unauthenticated remote attacker to inject and execute arbitrary system-level commands on the underlying server host. Given the critical CVSS v3.1 base score of 9.8, this flaw presents a significant risk for complete system compromise. Defenders should prioritize identifying instances of NUMail within their infrastructure and monitor for unauthorized process execution originating from the web application's service account. There is currently no evidence of public exploit code or active exploitation campaigns, but the simplicity of the injection vector necessitates immediate risk assessment and implementation of network-level controls.

## Impact

Successful exploitation leads to unauthenticated remote code execution with the privileges of the NUMail application, potentially resulting in full server compromise, unauthorized access to email data, and lateral movement within the network.

## Recommendation

- Perform an asset inventory to identify all instances of NUMail in the environment.
- Patch all affected NUMail installations as soon as a security update is provided by Green-Computing.
- Implement strict ingress filtering to limit access to NUMail management interfaces to trusted IP addresses only.
- Monitor web server access logs for anomalous characters (e.g., ;, |, &, $, `) in request parameters, which are typical indicators of command injection attempts.
