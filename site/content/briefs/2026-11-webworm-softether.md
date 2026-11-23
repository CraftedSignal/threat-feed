---
brief_id: brief-2026-11-23-webworm-softether
event_id: brief-2026-11-23-webworm-softether
revision: 1
activity_at: "2026-11-23T18:50:19Z"
title: Webworm Group Modifies SoftEther VPN for Evasion
slug: 2026-11-webworm-softether
description: The threat actor Webworm is using a recompiled version of SoftEther VPN Bridge to establish covert remote access by modifying the application's detection fingerprints and disguising it as network monitoring software.
date: "2026-11-23T18:50:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
actors:
  - Webworm
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Content verified against provided threat intelligence source.
tags:
  - malware
  - espionage
  - evasion
  - vpn
  - windows
products:
  - SoftEther VPN Bridge (4.44 build 9807)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The modified variant 'implements various tricks to hide itself from security tools,' and is disguised as network-monitoring software.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Webworm is suspected to be using a custom version of the open-source SoftEther VPN Bridge tool in an attempt to remove recognizable detection fingerprints.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: One of the most noticeable changes identified in the altered version is the use of innocuous-looking HTTP endpoints /update/alive.cgi and /update/picture.cgi.
    confidence_band: high
references:
  - https://thehackernews.com/2026/11/webworm-suspected-of-modifying.html
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify binaries masquerading as network monitoring software that contain embedded SoftEther VPN code, specifically checking for the 'RCEN' header in configuration files.
      technique_id: T1036
      data_needed:
        - File system scans for files containing the 'RCEN' string in the header.
        - Process creation events for binaries with non-standard names but SoftEther-like PDB paths.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The encrypted configuration starts with the magic bytes 'RCEN' in ASCII.
---

## Overview

Webworm, a China-aligned nation-state threat actor, has been observed using a custom-built, modified version of the open-source SoftEther VPN Bridge tool. The modifications focus on stealth and detection evasion rather than adding new functional capabilities. The actor compiles the tool from source and rebrands the binary as 'NtMonitor VPN', masquerading as 'Network Monitor Software' from a fictional entity called Network Systems Solutions Inc. The tool's configuration files are encrypted using a custom algorithm starting with the 'RCEN' magic bytes, and the application's internal HTTP communication endpoints and protocol handshake watermarks have been altered to avoid signature-based detection.

## Impact

The use of this modified VPN tool allows the actor to establish and maintain covert remote access to compromised networks while bypassing traditional security signatures and indicators related to standard SoftEther VPN deployments.

## Recommendation

- Audit environments for the presence of 'netcapa.exe' or binaries masquerading as network monitoring software that share the internal structure of SoftEther VPN.
- Investigate systems for unexpected network communication to unknown endpoints using custom protocol handshakes that deviate from the standard SoftEther VPN traffic baseline.
- Monitor for the creation of configuration files on disk with the 'RCEN' magic byte header.
- Implement detection for the presence of renamed SoftEther binaries where registry keys or internal metadata may still contain references to 'SoftEther Project'.
