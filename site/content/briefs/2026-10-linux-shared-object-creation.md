---
title: Detection of Suspicious Shared Object Creation on Linux
slug: 2026-10-linux-shared-object-creation
description: This brief addresses the detection of unauthorized shared object (.so) file creation in sensitive system directories, a technique commonly used by attackers for persistence and code injection on Linux systems.
date: "2026-10-05T12:01:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - linux
  - endpoint-security
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: The creation of a shared object file involves compiling code into a dynamically linked library that can be loaded by other programs at runtime.
    confidence_band: high
rules:
  - title: Detect Suspicious Shared Object Creation
    description: Detects the creation of shared object files in critical system directories by unknown processes, which may indicate persistence or unauthorized code injection.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.002
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the Sigma rule to the SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit rule logic for detection
  hunt_leads:
    - lead: Search for recently created .so files in sensitive paths not associated with known package managers
      technique_id: T1546.002
      data_needed:
        - File system audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker persistence via shared objects observed in previous research
  mitigation_plan:
    - priority: medium
      action: Implement strict file integrity monitoring (FIM) on /usr/lib and /lib directories
      owner: IT Operations
      addresses: Persistence via file modification
      evidence: Industry standard practice for Linux system integrity
---

Monitoring for the creation of shared object files is critical for identifying persistence mechanisms on Linux endpoints. Attackers often compile malicious code into dynamically linked libraries (.so files) and place them in system directories to achieve execution, inject functionality into legitimate processes, or bypass security controls at runtime. While legitimate system management tasks, such as software updates or application installations, frequently involve the creation of these files, malicious activity is often characterized by the use of previously unknown or uncommon processes performing these actions outside of standard package management workflows. By tracking file creation events in sensitive library paths, security teams can identify potentially unauthorized library loading or backdooring of applications that would otherwise evade standard process-based detection.

## Impact

Successful exploitation allows for stealthy persistence, privilege escalation via code injection, and potential bypass of security monitoring. Compromised systems may experience reduced integrity and confidentiality as malicious libraries interact with system-level services and user applications. If left undetected, this allows attackers to maintain long-term access, execute unauthorized code within the context of trusted processes, and exfiltrate sensitive data.

## Recommendation

Prioritize the investigation of file creation events in sensitive directories triggered by unknown processes. 
- Deploy the provided Sigma rule to detect the creation of shared object files in system-wide library paths.
- Tune existing detection logic by creating allowlists for known-good administrative processes and package managers documented in the Sigma filter.
- Utilize OSQuery to perform ad-hoc investigation of suspect shared objects, checking for file ownership, modification times, and associated process trees.
- Investigate the parent process of any suspicious .so creation to determine the execution chain and evaluate if the binary originates from a trusted source.
