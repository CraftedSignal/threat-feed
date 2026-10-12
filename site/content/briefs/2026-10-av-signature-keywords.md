---
title: Detection of Malicious Activity via Anti-Virus Application Logs
slug: 2026-10-av-signature-keywords
description: This detection brief provides a comprehensive list of keyword signatures for identifying malicious tool and malware execution artifacts within the Windows Application event log.
date: "2026-10-12T14:33:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - anti-virus
  - detection-engineering
  - windows
  - monitoring
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
    evidence: Detects potentially highly relevant antivirus events in the application log based on known virus signature names and malware keywords.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/Other/win_av_relevant_match.yml
rules:
  - title: Detect Malicious Tool and Malware Keywords in Application Logs
    description: Detects potentially relevant antivirus events in the Windows application log based on known threat signatures and malware-related keywords.
    platform: sigma
    severity: high
    tactics:
      - resource-development
    techniques:
      - T1588
    data_sources:
      - application
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Application log events containing identified malware/hacktool keywords
      technique_id: T1588
      data_needed:
        - Windows Event Log (Application)
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Source provides list of signatures for detection
---

This brief addresses the identification of malicious tools, hacking frameworks, and malware families by monitoring Windows Application event logs for specific anti-virus detection keywords. Organizations often maintain logs of security product activity; these logs frequently contain metadata identifying the specific threat detected. By surfacing these detections, security operations centers can identify reconnaissance tools (like AdFind), credential dumpers (like Mimikatz or SharpDump), and post-exploitation frameworks (like Cobalt Strike, Sliver, or Metasploit) that have been flagged by endpoint protection software. This approach is useful for identifying threats that may have been partially mitigated but represent ongoing signs of active compromise within the environment.

## Impact

Successful exploitation of the identified tools typically leads to credential theft, lateral movement, persistent remote access, or data encryption via ransomware. Identifying these signatures provides early warning of an attacker presence, allowing for rapid containment before broader environmental damage occurs.

## Recommendation

Deploy the provided Sigma rule to scan existing Windows Application log telemetry. Prioritize alerts triggered by these signatures as they often indicate confirmed malicious activity blocked or flagged by AV engines.

- Deploy the Sigma rule to the SIEM and filter out noisy, low-severity informational events to reduce false positive volume.
- Review and tune the exclusion list (filter_optional_generic) to account for organization-specific administrative tooling that may trigger similar keyword matches.
