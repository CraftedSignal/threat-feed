---
title: Detection of PowerShell WindowsIdentity.GetCurrent Method Abuse
slug: 2026-10-powershell-user-discovery
description: Adversaries leverage the .NET WindowsIdentity.GetCurrent() method via PowerShell to perform system owner discovery, aiding in situational awareness and lateral movement.
date: "2026-10-12T17:45:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: Adversaries may use this method to identify the logged-in user on a compromised endpoint, aiding in situational awareness and Active Directory discovery.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1033/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1033/T1033.yaml
rules:
  - title: Detect PowerShell WindowsIdentity.GetCurrent Method Usage
    description: Detects the use of the .NET WindowsIdentity.GetCurrent() method via PowerShell, often used by adversaries for system owner discovery.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for PowerShell user discovery attempts
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic requirement
  hunt_leads:
    - lead: Search for PowerShell command lines containing 'WindowsIdentity' or 'GetCurrent'
      technique_id: T1033
      data_needed:
        - Endpoint process creation logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source detection search logic
  mitigation_plan:
    - priority: medium_term
      action: Restrict unnecessary PowerShell access and enforce constrained language mode
      owner: IT Operations
      addresses: T1033
      evidence: General security hardening
---

Adversaries frequently conduct system owner discovery to understand the security context of a compromised endpoint. A common technique for this involves invoking the .NET 'WindowsIdentity.GetCurrent()' method via PowerShell. By querying the logged-in user context, attackers gain essential situational awareness, allowing them to map user privileges and identify high-value targets for further exploitation or lateral movement. This activity is often a precursor to more advanced post-exploitation phases within an Active Directory environment. Defenders should monitor for PowerShell executions containing specific .NET library references that indicate this discovery activity.

## Attack Chain

1. Initial access is established on a target endpoint via phishing or exploit.
2. The attacker identifies the environment as Windows and determines that PowerShell is available.
3. The attacker executes `powershell.exe` via the command line or an existing shell.
4. The attacker passes a command-line argument containing 'System.Security.Principal.WindowsIdentity' or 'GetCurrent()' to the PowerShell process.
5. The .NET method executes in-memory to retrieve the current user's security token.
6. The process output provides the attacker with the username and security identifier (SID) of the current session.
7. The attacker uses this identity to inform subsequent lateral movement or privilege escalation attempts.

## Impact

This technique provides attackers with critical identity context, which is a prerequisite for effective lateral movement and privilege escalation in enterprise networks. Successful discovery enables attackers to prioritize high-value targets, such as administrators, leading to potential full domain compromise and unauthorized access to sensitive corporate resources.

## Recommendation

Detection engineering teams should implement monitoring for PowerShell process creation events that include references to specific .NET identity classes.

- Deploy the Sigma rule provided in this brief to detect suspicious PowerShell command-line arguments.
- Enable process creation logging (Sysmon Event ID 1 or Windows Event Log 4688) to capture full command-line arguments.
- Review and tune the detection logic to account for legitimate administrative tasks or automated maintenance scripts that may perform user identity verification.
