---
title: Detection of Suspicious Dir Piped to Findstr Activity
slug: 2026-08-dir-piped-findstr
description: Adversaries frequently leverage the 'dir' command piped to 'findstr' for reconnaissance to identify sensitive files and credentials on compromised Windows systems.
date: "2026-08-07T15:14:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - reconnaissance
  - endpoint-security
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1119
    technique_name: Automated Exfiltration
    evidence: This technique is commonly used by attackers during the reconnaissance phase to enumerate files, directories, or sensitive data by filtering directory listings for specific strings or patterns.
    confidence_band: high
rules:
  - title: Detect Windows Dir Piped to Findstr
    description: Detects the execution of the 'dir' command piped to 'findstr', a common pattern used by attackers for reconnaissance and file discovery.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1119
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule and baseline administrative command line patterns.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic for identifying reconnaissance activity.
  hunt_leads:
    - lead: Search historical process logs for high-frequency or anomalous 'dir' piping patterns.
      technique_id: T1119
      data_needed:
        - Process command line arguments
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source notes that attackers use this for discovery.
  mitigation_plan:
    - priority: medium_term
      action: Restrict command line utility access if not required by users.
      owner: IT Operations
      addresses: T1119
      evidence: General security best practice.
---

This detection focuses on the execution of the Windows 'dir' command piped to the 'findstr' utility. This pattern is commonly observed during the reconnaissance and discovery phases of an attack. Attackers use this combination to efficiently enumerate directories and filter output for specific strings, such as passwords, configuration files, or sensitive document extensions. While this command sequence can be used by system administrators for routine maintenance or file searching, its presence in an environment often indicates an adversary mapping the file system to identify targets for exfiltration or lateral movement. Defenders should baseline common administrative scripting activity to minimize false positives while identifying anomalous reconnaissance patterns.

## Impact

Successful reconnaissance via this technique allows an attacker to identify high-value targets, configuration files containing hardcoded credentials, and sensitive data residing on the local file system. This intelligence gathering typically precedes further exploitation, data exfiltration, or lateral movement, significantly increasing the risk of credential compromise and unauthorized access to organizational data.

## Recommendation

- Deploy the provided Sigma rule to your SIEM environment to monitor process-creation events for the specified command-line pattern.
- Establish a baseline of legitimate administrative scripts and user behavior that utilize 'dir' and 'findstr' to tune out frequent false positives.
- Enable Sysmon or Windows Event Log 4688 to ensure full command-line visibility is captured and indexed for security analysis.
