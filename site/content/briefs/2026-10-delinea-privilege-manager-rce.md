---
brief_id: brief-2026-10-30-delinea-privilege-manager-rce
event_id: brief-2026-10-30-delinea-privilege-manager-rce
revision: 1
activity_at: "2026-10-30T20:01:24Z"
title: Delinea Privilege Manager Agent Remote Code Execution (CVE-2026-92744)
slug: 2026-10-delinea-privilege-manager-rce
description: An unauthenticated remote code execution vulnerability in the Delinea Privilege Manager Windows agent allows attackers to achieve system-level code execution by exploiting an insecure WCF callback endpoint on TCP 5593.
date: "2026-10-30T20:01:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Validated via vendor release notes and researcher PoC details
cpes:
  - cpe:2.3:a:delinea:privilege_manager_windows_core_agent:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - delinea
  - privilege-escalation
vendors:
  - Delinea
products:
  - Privilege Manager Windows Core agent (10.1.0 - 12.0.5796)
  - Privilege Manager Windows Core agent (13.0.0 - 13.0.1058)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated RCE in Delinea Privilege Manager Windows agent via WCF endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: '...run it in a PowerShell runspace as nt authority\system, with ExecutionPolicy.Bypass explicitly set.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: OnRegistrationComplete writes attacker-supplied certificates into LocalMachine\Ams — the store the agent uses to verify policy signatures
    confidence_band: high
cves:
  - id: CVE-2026-92744
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=CA816CA3-2780-5898-8B44-7B2FD4C940EB
  - https://sploitus.com/exploit?id=CA816CA3-2780-5898-8B44-7B2FD4C940EB&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block inbound TCP 5593 on all Windows endpoints running Delinea Privilege Manager
      owner: IT Operations
      due: 24h
      evidence: Delinea documented mitigation; inbound host wires that validator in as a custom validation mode
  hunt_leads:
    - lead: Identify inbound connections to TCP 5593 from external or unexpected internal IP ranges
      technique_id: T1190
      data_needed:
        - Firewall logs
        - Endpoint connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The agent hosts the callback listener on all interfaces
  mitigation_plan:
    - priority: immediate
      action: Upgrade Privilege Manager agent to 12.0.5804 or 13.0.2064
      owner: IT Operations
      addresses: CVE-2026-92744
      evidence: Fixed in Agent 12.0.5804 (v12) and 13.0.2064 (v13)
---

Delinea Privilege Manager Windows agents (v12.x and v13.x) contain a critical vulnerability (CVE-2026-92744) in the WCF duplex callback service listening on TCP 5593. The agent fails to validate client certificates due to an empty custom validator method and uses 'ProtectionLevel.None', allowing unauthenticated remote callers to interact with the service. Exploitation enables an attacker to overwrite the 'LocalMachine\Ams' trust store and trigger task execution as 'NT AUTHORITY\SYSTEM' via PowerShell. This vulnerability was reported by CyberCrew and fixed in version 12.0.5804 and 13.0.2064.

## Attack Chain

1. Attacker performs network reconnaissance to identify Privilege Manager agents listening on TCP 5593.
2. Attacker initiates a connection to the WCF duplex callback endpoint on the target agent.
3. Attacker presents a self-signed, attacker-generated certificate, which the agent accepts due to an empty 'AmsServerCertValidator.Validate()' method.
4. Attacker calls the 'OnRegistrationComplete' operation, providing a malicious server certificate payload.
5. Agent service overwrites the 'LocalMachine\Ams' certificate store with the attacker-provided certificate, effectively becoming the trusted policy authority for the agent.
6. Attacker calls 'OnClientTaskQueued' with a synthetic 'CommandId' to force the agent to fetch a malicious task.
7. Agent executes the attacker-defined PowerShell command in a runspace as 'NT AUTHORITY\SYSTEM'.

## Impact

Successful exploitation grants an attacker full control over the agent host with 'SYSTEM' privileges. Since the agent governs process elevation and policy enforcement, the attacker can manipulate security decisions and execute arbitrary code.

## Recommendation

* Upgrade Privilege Manager Windows Core agent to version 12.0.5804 (for v12 environments) or 13.0.2064 (for v13 environments).
* Apply the documented Delinea mitigation immediately: block all inbound traffic to TCP 5593 on all agent hosts.
* Monitor host-based firewall logs for inbound connections to TCP 5593 originating from unauthorized IP addresses.
* Hunt for unexpected PowerShell execution by the 'Delinea Privilege Manager' service process or child processes spawned by the agent.
