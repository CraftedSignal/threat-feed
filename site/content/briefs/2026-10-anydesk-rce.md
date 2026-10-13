---
title: AnyDesk Arbitrary Code Execution Vulnerability
slug: 2026-10-anydesk-rce
description: AnyDesk contains a vulnerability that allows a remote, unauthenticated attacker to execute arbitrary code with administrator privileges on affected Windows systems.
date: "2026-10-13T18:29:44Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - AnyDesk
products:
  - AnyDesk
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in AnyDesk ausnutzen
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Schwachstelle ermöglicht Ausführen von beliebigem Programmcode mit Administratorrechten
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Schwachstelle ermöglicht Ausführen von beliebigem Programmcode mit Administratorrechten
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3882
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all systems running AnyDesk
      owner: IT Operations
      due: 24h
      evidence: AnyDesk is affected by a critical vulnerability
  mitigation_plan:
    - priority: immediate
      action: Check vendor for patches and apply to all AnyDesk installations
      owner: IT Operations
      addresses: AnyDesk arbitrary code execution vulnerability
      evidence: Schwachstelle ermöglicht Ausführen von beliebigem Programmcode mit Administratorrechten
---

AnyDesk is affected by a critical vulnerability that permits a remote, unauthenticated attacker to execute arbitrary code with system-level administrator privileges. This flaw bypasses standard security controls, effectively granting full control over the host machine. Given AnyDesk's role as a remote desktop utility, the software typically runs with high privileges, making it a high-value target for remote exploitation. The vulnerability allows for complete system compromise, enabling attackers to deploy secondary payloads, exfiltrate sensitive data, or establish persistent access within the target network. Defenders should treat any unauthorized or anomalous activity involving the AnyDesk binary as a potential compromise of the host.

## Impact

Successful exploitation leads to a complete takeover of the affected host with administrator privileges. This impact spans the confidentiality, integrity, and availability of the system. Organizations utilizing AnyDesk for remote management are at risk of large-scale credential harvesting, lateral movement into internal segments, and ransomware deployment.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Inventory all systems running AnyDesk software to identify potential exposure points.
- Review network logs for unexpected inbound connections targeting the default AnyDesk communication ports.
- Monitor endpoint process creation logs for the AnyDesk binary spawning suspicious child processes (e.g., cmd.exe, powershell.exe, or unknown executables).
- Consult the vendor documentation or official support channels for available patches and apply them immediately across the environment.
