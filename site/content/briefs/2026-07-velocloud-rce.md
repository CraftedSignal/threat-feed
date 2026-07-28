---
title: Vulnerability in VeloCloud Orchestrator On-Prem Allows Remote Code Execution
slug: 2026-07-velocloud-rce
description: A critical vulnerability has been identified in VeloCloud Orchestrator (VCO) On-Prem that allows for remote code execution, enabling a remote attacker to gain privileged access, execute arbitrary commands on the VCO host, and potentially install programs, modify or delete data, or create new user accounts with administrative rights, with impact severity depending on the service account privileges.
date: "2026-07-28T14:22:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - network
  - sd-wan
  - sase
vendors:
  - VeloCloud
products:
  - VeloCloud Orchestrator On-Prem
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute commands
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: access privileged internal functionality, execute commands, and impact the VCO host. Depending on the privileges associated with the service account
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1106
    technique_name: Native API
    evidence: install programs; view, change, or delete data; or create new accounts with full user rights
    confidence_band: med
references:
  - https://www.cisecurity.org/advisory/a-vulnerability-in-velocloud-orchestrator-vco-on-prem-could-allow-for-remote-code-execution_2026-072
---

A critical vulnerability has been discovered in VeloCloud Orchestrator (VCO) On-Prem, a centralized management platform for software-defined wide area networks (SD-WAN) and SASE components. This flaw could allow a remote attacker to achieve remote code execution (RCE) on the VCO host. The vulnerability grants unauthorized access to privileged internal functionality, allowing the execution of arbitrary commands. This could lead to severe consequences, including the ability to install malicious programs, view, alter, or delete sensitive data, or create new user accounts with full administrative privileges. The specific impact on a system depends directly on the privilege level configured for the service account associated with the exploited VCO instance, making systems with administrative account privileges highly susceptible to complete compromise.

## Attack Chain

1. A remote attacker identifies a vulnerable VeloCloud Orchestrator (VCO) On-Prem instance exposed to the network.
2. The attacker exploits the vulnerability to gain unauthorized access to privileged internal functionality within the VCO platform.
3. Leveraging this access, the attacker successfully executes arbitrary commands on the underlying VCO host.
4. Depending on the initial privileges obtained, the attacker may perform privilege escalation to gain higher-level system access.
5. The attacker proceeds to impact the VCO host by installing programs, viewing, changing, or deleting sensitive data, or creating new accounts with full user rights.
6. With control over the VCO, the attacker could potentially manipulate the managed SD-WAN and SASE components, affecting network operations and security.

## Impact

Successful exploitation of this vulnerability could lead to a complete compromise of the VeloCloud Orchestrator On-Prem host. An attacker could gain administrative control, allowing them to install arbitrary programs, modify or exfiltrate sensitive configuration data, delete critical files, and create new user accounts with full administrative rights. The extent of the damage is directly tied to the privileges of the exploited service account; systems running VCO with highly privileged accounts face the risk of total system takeover and potential disruption or manipulation of the entire SD-WAN and SASE infrastructure managed by the orchestrator.

## Recommendation

* Patch VeloCloud Orchestrator On-Prem immediately upon release of an official security update from VeloCloud to remediate the undisclosed vulnerability.
* Restrict network access to VeloCloud Orchestrator (VCO) On-Prem instances, ensuring they are not directly exposed to the public internet unless absolutely necessary, to mitigate remote exploitation attempts.
* Implement the principle of least privilege for all service accounts associated with VCO On-Prem components to limit the potential impact of successful exploitation.
