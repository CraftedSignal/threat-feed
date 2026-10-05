---
title: Detection of Unauthorized Security Service Termination on Windows
slug: 2026-10-windows-security-service-stoppage
description: Adversaries frequently attempt to disable security-related services on Windows endpoints using standard administration tools to facilitate defense evasion and destructive activity.
date: "2026-10-05T12:17:53Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - defense-evasion
  - windows
  - endpoint-security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The following analytic detects attempts to stop security-related services on an endpoint, which may indicate malicious activity.
    confidence_band: high
rules:
  - title: Detect Attempted Security Service Termination
    description: Detects the use of sc.exe, net.exe, or PowerShell Stop-Service to stop security-related services
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
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
    - action: Deploy detection rule to identify service termination attempts
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for identifying service termination TTPs
  hunt_leads:
    - lead: Search for non-standard parent processes executing service stop commands
      technique_id: T1562.001
      data_needed:
        - Process creation logs with parent process context
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries often mask this activity by executing commands via cmd.exe or obfuscated scripts
  mitigation_plan:
    - priority: medium_term
      action: Enforce least privilege for service management on endpoints
      owner: IT Operations
      addresses: T1562.001
      evidence: Source documentation identifies stopping security services as a privilege escalation and evasion risk
---

Adversaries often attempt to terminate security-related services on Windows endpoints as a critical step in their attack lifecycle. By disabling antivirus, endpoint detection and response (EDR), or other security software, threat actors aim to bypass defensive measures to achieve persistence, exfiltration, or data destruction. This activity is frequently observed in high-impact campaigns, including those involving destructive malware like WhisperGate or information stealers such as Trickbot and Azorult.

Defenders can identify this behavior by monitoring for the misuse of built-in administrative tools such as 'sc.exe', 'net.exe', or PowerShell 'Stop-Service' cmdlets directed at known security service names. Because legitimate administrative maintenance may occasionally involve stopping services, this detection is most effective when cross-referenced against a lookup table of security-critical services. Failure to detect this activity can lead to a complete loss of endpoint visibility, allowing an attacker to operate undetected during the later stages of an intrusion.

## Attack Chain

1. Attacker gains initial access to the Windows endpoint via phishing or exploit.
2. Attacker executes discovery commands to identify running security products.
3. Attacker identifies the specific service names associated with the security software.
4. Attacker launches 'sc.exe', 'net.exe', or PowerShell with administrative privileges.
5. Attacker invokes the 'stop' command or 'Stop-Service' cmdlet against the target security service.
6. The service is successfully terminated, disabling the defensive telemetry feed.
7. Attacker proceeds with follow-on activities such as data wiping or payload installation.

## Impact

Successful termination of security services severely undermines the defensive posture of the organization. It renders the endpoint blind to subsequent malicious actions, potentially leading to widespread data destruction, theft of credentials, and full system compromise. This TTP has been observed in attacks targeting critical infrastructure and organizations globally, resulting in significant operational downtime and data loss.

## Recommendation

1. Deploy the provided Sigma rule to monitor process executions targeting security services.
2. Maintain a comprehensive, updated lookup table of authorized security services (e.g., AV daemons, EDR sensors) to filter out legitimate administrative restarts from malicious service termination.
3. Ensure that Sysmon Event ID 1 or Windows Event ID 4688 is actively ingested into the SIEM, capturing full command-line arguments.
4. Restrict local administrative privileges to reduce the ability of unauthorized users to modify service states.
