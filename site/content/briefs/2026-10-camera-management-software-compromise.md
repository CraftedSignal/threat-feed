---
brief_id: brief-2026-10-28-camera-management-software-compromise
event_id: brief-2026-10-28-camera-management-software-compromise
revision: 1
activity_at: "2026-10-28T11:38:20Z"
title: Camera Management Software Compromised for Malware Deployment
slug: 2026-10-camera-management-software-compromise
description: Attackers are exploiting camera management software to gain initial access and deploy malware via DLL sideloading using the legitimate Windows process WpcMon.exe.
date: "2026-10-28T11:38:20Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
tags:
  - initial-access
  - persistence
  - c2
  - defense-evasion
  - malware
products:
  - CMS (Camera Management Software)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    subtechnique_id: T1574.002
    subtechnique_name: DLL Side-Loading
    evidence: attackers ... abused the legitimate Windows binary WpcMon.exe to sideload malicious DLLs
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    subtechnique_id: T1547.001
    subtechnique_name: Registry Run Keys / Startup Folder
    evidence: established Run Key persistence
    confidence_band: high
references:
  - https://www.huntress.com/blog/camera-management-software-compromise-malware
iocs:
  - type: ip
    value: 144.172.116.37
  - type: domain
    value: 3r-dataware.com
  - type: url
    value: http://cloudapi.3r-dataware.com/sso/
ioc_counts:
  domain: 1
  ip: 1
  url: 1
rules:
  - title: Detect WpcMon.exe Sideloading Behavior
    description: Detects the execution of the legitimate Windows binary WpcMon.exe which is being abused for DLL sideloading in user-writable paths
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1574.002
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
    - action: Block 144.172.116.37 at network egress
      owner: SOC
      due: 24h
      evidence: C2 beaconing address identified in report
  hunt_leads:
    - lead: Identify presence of CMS.exe or WpcMon.exe execution in AppData paths
      technique_id: T1574.002
      data_needed:
        - EDR process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers utilize CMS.exe as initial access and WpcMon.exe for sideloading
  mitigation_plan:
    - priority: immediate
      action: Apply AppLocker or EDR block rules for WpcMon.exe execution in non-standard paths
      owner: IT Operations
      addresses: T1574.002
      evidence: Abuse of WpcMon.exe for sideloading
---

Huntress identified a campaign involving the compromise of camera management software (CMS.exe) to facilitate unauthorized access to enterprise environments. Following initial access, the attackers deployed a malicious binary (rs.win32.exe), performed DLL sideloading using the legitimate Windows Parental Controls Monitor (WpcMon.exe), established persistence via registry Run keys, and beaconed to a C2 server. 

## Attack Chain
1. Initial access via exploitation of camera management software (CMS.exe).
2. Deployment of malicious binary 'rs.win32.exe' to the endpoint.
3. Execution of 'WpcMon.exe' to perform DLL sideloading in the user's AppData directory.
4. Establishment of persistence through Windows registry Run keys.
5. Establishment of outbound C2 communication to '144.172.116.37'.

## Recommendation
- Inventory and restrict access to camera management software; treat these applications as part of the enterprise attack surface.
- Implement monitoring for unauthorized process executions originating from 'CMS.exe'.
- Restrict execution of binaries and DLLs from user-writable paths such as '%AppData%'.
- Monitor for registry modifications targeting 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' or 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'.
- Block the identified C2 IP address '144.172.116.37' at the network perimeter.
