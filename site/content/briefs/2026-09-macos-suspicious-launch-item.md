---
title: Detection of Suspicious macOS Launch Item Registration
slug: 2026-09-macos-suspicious-launch-item
description: Adversaries leverage macOS launch agent and daemon registration to establish persistence by executing binaries from temporary or world-writable directories to evade standard security monitoring.
date: "2026-09-28T10:10:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - macos
  - endpoint
  - threat-detection
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Identifies the registration of a launch agent or launch daemon whose target executable resides in a temporary or user-writable location.
    confidence_band: high
references:
  - https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/
  - https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
rules:
  - title: Detect Suspicious macOS Launch Item Registration
    description: Detects the registration of a launch agent or daemon pointing to an executable in a suspicious or user-writable path.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
      - T1543.004
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the suspicious launch item detection rule.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific paths and BTM log structure.
  hunt_leads:
    - lead: Search for existing launch items referencing /tmp, /var/tmp, or /Users/Shared in existing BTM logs.
      technique_id: T1543
      data_needed:
        - macOS Security Events integration logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: BTM logs contain path data for all registered launch items.
---

Adversaries targeting macOS environments often establish persistence by registering malicious launch agents or launch daemons. These components are defined by property list (plist) files which specify a target executable to run upon system or user startup. To avoid detection, threat actors frequently stage these malicious executables within temporary, world-writable, or user-accessible directories such as /tmp, /var/tmp, /var/folders, /Users/Shared, or specific user-level cache and download directories. 

Legitimate software typically resides in protected system or application paths. By identifying launch items that point to suspicious locations, security teams can detect non-standard persistence mechanisms used by malware, such as the CloudMensis spyware, to maintain long-term access. Monitoring the BackgroundTaskManagement (BTM) subsystem logs allows for visibility into the registration of these items, providing a critical defensive measure against unauthorized background process execution.

## Attack Chain

1. An attacker gains initial access to the macOS endpoint.
2. The attacker stages a malicious payload (executable binary) into a temporary or world-writable directory (e.g., /tmp/malware).
3. The attacker crafts a malicious property list (plist) file pointing to the staged binary path.
4. The attacker triggers the registration of the launch item using launchctl or the BTM subsystem.
5. The macOS BackgroundTaskManagement subsystem records the registration, including the plist path and the target executable path.
6. The system automatically executes the binary from the temporary location upon next user login or system reboot.
7. The malware achieves persistence, enabling ongoing malicious operations on the target host.

## Impact

Successful exploitation allows attackers to maintain persistence on macOS systems, facilitating ongoing espionage, exfiltration of sensitive data, or delivery of secondary payloads. Unauthorized background processes running with user or system privileges can bypass standard user-space restrictions, potentially leading to full host compromise.

## Recommendation

Deploy detection rules targeting the registration of launch agents and daemons with executables residing in non-standard paths. 
- Enable the macOS Security Events integration to collect BackgroundTaskManagement logs.
- Implement the provided rule to alert on launch items referencing temporary or user-writable directories.
- Investigate any triggered alerts by analyzing the origin of the executable and the lifecycle of the associated plist file.
- Perform manual reviews of persistent launch items that reside outside of /Applications or /System directories.
