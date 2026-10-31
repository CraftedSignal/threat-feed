---
brief_id: brief-2026-10-31-puwell-rce
event_id: brief-2026-10-31-puwell-rce
revision: 1
activity_at: "2026-10-31T00:04:15Z"
title: 'Puwell IP Camera: Unauthenticated remote code execution via DebugShell (CVE-2026-61515)'
slug: 2026-10-puwell-rce
description: Puwell IP cameras (firmware 2.x - 4.x) contain an unauthenticated remote code execution vulnerability in a DebugShell interface on TCP port 34567, which is currently being targeted by botnets.
date: "2026-10-31T00:04:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:puwell:ip_camera:2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:puwell:ip_camera:4.0:*:*:*:*:*:*:*
tags:
  - iot
  - rce
  - vulnerability
  - iot-botnet
vendors:
  - Puwell
products:
  - IP Camera (firmware 2.x–4.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated RCE in Puwell IP Camera DebugShell on TCP 34567 via JSON commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: passes them to the shell without checking. Any who can reach the port executes commands as root.
    confidence_band: high
cves:
  - id: CVE-2026-61515
    cvss: 9.8
    epss: 0.02438
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=56BE1C3D-0D94-5265-90F2-AE170EDCDB82
  - https://sploitus.com/exploit?id=56BE1C3D-0D94-5265-90F2-AE170EDCDB82&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Puwell DebugShell Access
    description: Detects unauthorized connection attempts or traffic directed to the known Puwell DebugShell port 34567
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block TCP port 34567 at the network perimeter.
      owner: IT Operations
      due: 2h
      evidence: 'Mitigation section: Block 34567/tcp on WAN'
  hunt_leads:
    - lead: Identify child processes spawned by camera management services.
      technique_id: T1059.004
      data_needed:
        - Process tree telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Detection section: unexpected child processes of the camera service'
  mitigation_plan:
    - priority: immediate
      action: Upgrade Puwell IP Camera firmware.
      owner: IT Operations
      addresses: CVE-2026-61515
      evidence: 'Mitigation section: Update firmware'
  gaps:
    - Visibility into internal process execution on camera devices.
---

Puwell IP cameras running firmware versions 2.x through 4.x expose an undocumented 'DebugShell' interface on TCP port 34567. This interface processes JSON-formatted commands without requiring authentication and executes them directly via the system shell with root-level privileges. A functional proof-of-concept exploit is publicly available. The vulnerability has been identified as a vector in real-world botnet campaigns targeting IoT infrastructure.

## Impact

Successful exploitation allows for complete system compromise, including unauthorized command execution with root privileges, data exfiltration, and potential integration of the camera into an IoT botnet.

## Recommendation

- Immediately block inbound and outbound traffic on TCP port 34567 at the network perimeter (WAN firewall) for all Puwell IP cameras.
- Isolate all affected IP cameras into a restricted VLAN with no direct internet access; limit access to the internal network to authorized NVR systems only.
- Disable UPnP on all camera devices to prevent automated port exposure.
- Review firmware release notes for Puwell IP cameras and upgrade to any version post-4.x that addresses this DebugShell exposure.
- Audit logs for established connections to TCP 34567 and subsequent execution of unauthorized child processes originating from the camera service.
