---
brief_id: brief-2026-11-10-macos-sysctl-discovery
event_id: brief-2026-11-10-macos-sysctl-discovery
revision: 1
activity_at: "2026-11-10T02:40:16Z"
title: MacOS system information discovery via sysctl
slug: 2026-11-macos-sysctl-discovery
description: Threat actors and malware use the sysctl command on MacOS to retrieve hardware, kernel, and machine-dependent information for environment discovery and virtualization detection.
date: "2026-11-10T02:40:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - macos
  - discovery
  - evasion
affected_os:
  - MacOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: This process is primarily used to detect and avoid virtualization and analysis environments.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1497.001
    technique_name: System Checks
    evidence: It provides system hardware information. This process is primarily used to detect and avoid virtualization and analysis environments.
    confidence_band: high
references:
  - https://www.loobins.io/binaries/sysctl/#
  - https://web.archive.org/web/20240309235614/https://evasions.checkpoint.com/techniques/macos.html
  - https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
  - https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/
  - https://objective-see.org/blog/blog_0x1E.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_sysctl_discovery.yml
rules:
  - title: Detect MacOS System Information Discovery via Sysctl
    description: Detects the execution of sysctl with arguments commonly used by malware to retrieve hardware, kernel, and machine-dependent information to identify virtualized environments.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - stealth
    techniques:
      - T1082
      - T1497.001
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to your EDR or SIEM to flag sysctl discovery behavior.
      owner: Detection Engineering
      due: 7d
      evidence: Source documentation of sysctl usage for discovery.
---

The 'sysctl' utility on MacOS is frequently abused by threat actors to perform system discovery and to detect analysis environments. By querying specific namespaces such as 'hw.', 'kern.', and 'machdep.', malicious code can identify hardware specifications, kernel versions, and whether the process is running within a virtualized sandbox.

## Impact

This activity allows attackers to perform reconnaissance on the target machine and to implement evasion tactics, such as terminating execution if a virtualized environment or debugging tool is detected.

## Recommendation

Deploy the detection rule below to monitor for suspicious use of the 'sysctl' utility. Focus on process execution telemetry that includes these specific discovery arguments, and baseline administrative usage within your environment to minimize false positives.
