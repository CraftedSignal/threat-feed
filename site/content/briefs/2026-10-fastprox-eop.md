---
brief_id: brief-2026-10-27-fastprox-eop
event_id: brief-2026-10-27-fastprox-eop
revision: 2
activity_at: "2026-10-28T02:38:43Z"
revision_history:
  - revision: 2
    at: "2026-10-28T02:38:43Z"
    checksum: sha256:93dafd99f7798522fe00d6b837f064a9f1c31086d50727f0d2f828aa5766d66c
    summary: added coverage for Windows 10 1607 (< 10.0.14393.8246) +3 products
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WH04M1001-CVE-2025-48799&utm_source=rss&utm_medium=rss
title: 'Microsoft Windows: Fastprox privilege escalation (CVE-2026-69451)'
slug: 2026-10-fastprox-eop
description: A public proof-of-concept exploit for CVE-2026-69451 in the Windows Fastprox component enables local privilege escalation via arbitrary command execution.
date: "2026-10-27T14:03:13Z"
lastmod: "2026-10-28T02:37:55Z"
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
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*
tags:
  - windows
  - privilege-escalation
  - cve-2026-69451
  - wuauserv
vendors:
  - Microsoft
products:
  - Windows 10 1607 (< 10.0.14393.9512)
  - Windows 10 1809 (< 10.0.17763.9245)
  - Windows 10 21h2 (< 10.0.19044.7725)
  - Windows 10 22h2 (< 10.0.19045.7725)
  - Windows 10 1607 (< 10.0.14393.8246)
  - Windows 10 1809 (< 10.0.17763.7558)
  - Windows 10 21h2 (< 10.0.19044.6093)
  - Windows 10 22h2 (< 10.0.19045.6093)
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
  - id: CVE-2025-48799
    cvss: 7.8
    epss: 0.01257
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FJ016-CVE-2026-69451-POC
  - https://fj016.fr/blog/cve-2026-69451-en
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FJ016-CVE-2026-69451-POC&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WH04M1001-CVE-2025-48799
  - https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WH04M1001-CVE-2025-48799&utm_source=rss&utm_medium=rss
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
    - action: Patch affected Windows 10 systems to the baseline versions provided in the brief.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability requires patching the wuauserv service logic.
  hunt_leads:
    - lead: Search for recent executions of processes named fastprox_eop.exe or unusual CLI arguments referencing --cmd and --out
      technique_id: T1068
      data_needed:
        - Process execution logs (Sysmon EID 1 or EDR equivalent)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Public PoC usage instructions document these specific arguments
    - lead: Identify systems with multiple physical drives where the wuauserv process executes file deletion operations outside of standard Windows/SoftwareDistribution directories.
      technique_id: T1068
      data_needed:
        - File system auditing
        - Sysmon Event ID 23 (FileDelete)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit relies on arbitrary folder deletion by the Windows Update service.
  mitigation_plan:
    - priority: immediate
      action: Install security patches addressing CVE-2026-69451
      owner: IT Operations
      addresses: CVE-2026-69451
      evidence: Patch versions provided by vendor advisory
    - priority: immediate
      action: Apply Microsoft security updates for CVE-2025-48799.
      owner: IT Operations
      addresses: CVE-2025-48799
      evidence: Source identifies versions required to remediate the vulnerability.
updates:
  - at: "2026-10-28T02:37:55Z"
    level: L2
    summary: added coverage for Windows 10 1607 (< 10.0.14393.8246) +3 products
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WH04M1001-CVE-2025-48799&utm_source=rss&utm_medium=rss
---

CVE-2026-69451 is a high-severity vulnerability in the Windows Fastprox component. A proof-of-concept (PoC) tool titled "fastprox_eop.exe" has been published, which allows an attacker with low privileges to execute arbitrary commands on a compromised system. The exploit requires user interaction and is applicable to multiple versions of Windows 10.

## Impact

Successful exploitation allows a local attacker with low privileges to escalate their permissions to a higher integrity level, facilitating arbitrary command execution on the target system.

## Recommendation

1. Inventory all Windows 10 endpoints to identify systems running versions earlier than those listed in the affected products section.
2. Deploy the relevant Microsoft security updates to remediate CVE-2026-69451 on all identified vulnerable systems.
3. Monitor endpoint telemetry for unauthorized execution of "fastprox_eop.exe" or suspicious command lines involving the Fastprox component.
