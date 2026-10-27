---
brief_id: brief-2026-10-27-fastprox-eop
event_id: brief-2026-10-27-fastprox-eop
revision: 1
activity_at: "2026-10-27T14:03:13Z"
title: 'Microsoft Windows: Fastprox privilege escalation (CVE-2026-69451)'
slug: 2026-10-fastprox-eop
description: A public proof-of-concept exploit for CVE-2026-69451 in the Windows Fastprox component enables local privilege escalation via arbitrary command execution.
date: "2026-10-27T14:03:13Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for deployment
cpes:
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:x64:*
tags:
  - windows
  - privilege-escalation
  - cve-2026-69451
vendors:
  - Microsoft
products:
  - Windows 10 1607 (< 10.0.14393.9512)
  - Windows 10 1809 (< 10.0.17763.9245)
  - Windows 10 21h2 (< 10.0.19044.7725)
  - Windows 10 22h2 (< 10.0.19045.7725)
affected_os:
  - Windows 10
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: PoC for CVE-2026-69451 in Fastprox enabling command execution via EOP tool.
    confidence_band: high
cves:
  - id: CVE-2026-69451
    cvss: 7.1
    epss: 0.0057
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FJ016-CVE-2026-69451-POC
  - https://fj016.fr/blog/cve-2026-69451-en
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FJ016-CVE-2026-69451-POC&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Fastprox EOP Tool Execution
    description: Detects the execution of the identified Fastprox EOP PoC tool based on its documented command-line usage.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch vulnerable Windows 10 systems to the versions specified in the affected products list
      owner: IT Operations
      due: 72h
      evidence: Vulnerability (CVE-2026-69451) has a public PoC available
  hunt_leads:
    - lead: Search for recent executions of processes named fastprox_eop.exe or unusual CLI arguments referencing --cmd and --out
      technique_id: T1068
      data_needed:
        - Process execution logs (Sysmon EID 1 or EDR equivalent)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Public PoC usage instructions document these specific arguments
  mitigation_plan:
    - priority: immediate
      action: Install security patches addressing CVE-2026-69451
      owner: IT Operations
      addresses: CVE-2026-69451
      evidence: Patch versions provided by vendor advisory
---

CVE-2026-69451 is a high-severity vulnerability in the Windows Fastprox component. A proof-of-concept (PoC) tool titled "fastprox_eop.exe" has been published, which allows an attacker with low privileges to execute arbitrary commands on a compromised system. The exploit requires user interaction and is applicable to multiple versions of Windows 10.

## Impact

Successful exploitation allows a local attacker with low privileges to escalate their permissions to a higher integrity level, facilitating arbitrary command execution on the target system.

## Recommendation

1. Inventory all Windows 10 endpoints to identify systems running versions earlier than those listed in the affected products section.
2. Deploy the relevant Microsoft security updates to remediate CVE-2026-69451 on all identified vulnerable systems.
3. Monitor endpoint telemetry for unauthorized execution of "fastprox_eop.exe" or suspicious command lines involving the Fastprox component.
