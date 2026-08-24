---
title: Multiple Vulnerabilities in Rapid7 Velociraptor
slug: 2026-08-velociraptor-vulnerabilities
description: Rapid7 Velociraptor is affected by multiple vulnerabilities allowing an authenticated remote attacker to perform arbitrary file manipulation, security bypass, remote code execution, and privilege escalation.
date: "2026-08-24T15:55:50Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Rapid7
products:
  - Velociraptor
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerabilities allow an attacker to perform arbitrary code execution, which can be leveraged for persistence.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The advisory states vulnerabilities allow for privilege escalation.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2974
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all Velociraptor instances and verify current versioning.
      owner: IT Operations
      due: 24h
      evidence: Advisory requires action to address vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Patch Velociraptor server and agents to the latest version.
      owner: IT Operations
      addresses: Velociraptor vulnerabilities
      evidence: BSI Security Advisory
---

Rapid7 Velociraptor, an endpoint visibility and incident response tool, is affected by multiple vulnerabilities that enable an authenticated remote attacker to compromise system integrity and security posture. The vulnerabilities, as reported by the BSI, allow for arbitrary file manipulation, bypass of established security controls, remote code execution (RCE), and privilege escalation. 

Velociraptor is a powerful agent-based tool often deployed with high-level system privileges to facilitate forensic data collection and live response. Successful exploitation of these vulnerabilities is particularly critical because they allow a malicious actor with initial authentication to gain control over the endpoint agent, potentially leading to full administrative compromise of the underlying host. Defenders must prioritize patching or isolating affected instances until updates are applied, as this tool is a common target for attackers looking to subvert security monitoring capabilities or deploy persistent backdoors.

## Impact

Successful exploitation allows for complete system takeover, including the ability to execute arbitrary code with elevated privileges, manipulate forensic evidence, and bypass security monitoring controls. Given the tool's intended role in incident response and security auditing, its compromise provides attackers with stealthy persistence and deep visibility into the host environment, potentially impacting any enterprise network where Velociraptor is utilized for endpoint security management.

## Recommendation

* Review current deployment of Velociraptor and ensure all agents and the management server are updated to the latest vendor-provided release.
* Audit logs for authenticated sessions from unexpected or suspicious source IP addresses to identify potential unauthorized use of the management interface.
* Restrict administrative access to the Velociraptor management console to a minimal set of highly trusted users and utilize multi-factor authentication (MFA) where possible.
* Monitor for unauthorized file modifications or unexpected process executions originating from the Velociraptor binary or service accounts.
