---
title: Detection of Hidden Executables in NTFS Alternate Data Streams
slug: 2026-09-ads-hidden-exec
description: Adversaries utilize NTFS Alternate Data Streams (ADS) to conceal malicious executables, effectively bypassing basic file visibility checks and traditional security scans.
date: "2026-09-01T12:17:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - persistence
  - ads
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: The detection logic focuses on finding executable content hidden within alternate data streams, which aligns with T1564.004.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_ads_executable.yml
  - https://twitter.com/0xrawsec/status/1002478725605273600
rules:
  - title: Detect Hidden Executable In NTFS Alternate Data Stream
    description: Detects the creation of an NTFS Alternate Data Stream (ADS) containing an executable by identifying non-empty Imphash values associated with stream creation events.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1564.004
    data_sources:
      - create_stream_hash
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for files with the ':' separator in filenames in Sysmon Event ID 15 logs.
      technique_id: T1564.004
      data_needed:
        - Sysmon Event ID 15
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source document identifies ADS as a stealth mechanism.
---

Attackers leverage the NTFS Alternate Data Stream (ADS) feature to store hidden executables within legitimate files. This technique allows malicious payloads to persist on a system without appearing in standard directory listings or being easily detected by basic file integrity monitoring tools. By attaching an executable stream to a host file (e.g., file.txt:malware.exe), an actor can execute the hidden component using Windows binaries like 'wmic' or 'rundll32'. Defenders often overlook ADS content, making it an effective method for staging malware or maintaining persistence in compromised environments. This brief focuses on the detection of such streams by monitoring for the creation of non-null Imphash values associated with ADS file events.

## Impact

Successful exploitation allows attackers to execute arbitrary code while obfuscating the malicious binary from standard forensic analysis and basic endpoint detection. This technique is frequently observed in malware staging, lateral movement, and persistent backdoor deployment, complicating incident response and threat hunting efforts.

## Recommendation

* Deploy the provided Sigma rule to identify the creation of suspicious streams containing executable content.
* Enable Sysmon Event ID 15 (FileStreamHash) to capture the necessary telemetry for detecting ADS activity.
* Configure security tools to alert on non-standard stream creation events originating from non-installer processes.
* Investigate occurrences of hidden streams to differentiate between legitimate software packaging and malicious staging activity.
