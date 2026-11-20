---
brief_id: brief-2026-11-18-windows-vulnerabilities
event_id: brief-2026-11-18-windows-vulnerabilities
revision: 2
activity_at: "2026-11-20T01:35:29Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:35:29Z"
    checksum: sha256:219fdd2a4990f3e3a9d3711487ea989f2cbd5fe4b99619082eb815cfc6016604
    summary: added coverage for Windows 10 (Version 1607, 1809, 21H2, 22H2) +7 products
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - content
      - cpes
      - cves
      - has_poc
      - lastmod
      - poc_references
      - priority
      - priority_score
      - priority_signals
      - references
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NHH9905-CVE-2026-62735&utm_source=rss&utm_medium=rss
title: 'Microsoft Windows: http.sys integer overflow (CVE-2026-62735)'
slug: 2026-11-windows-vulnerabilities
description: An integer overflow in the http.sys kernel driver allows local attackers to trigger a heap overflow, potentially resulting in privilege escalation to SYSTEM.
date: "2026-11-18T09:19:28Z"
lastmod: "2026-11-20T01:34:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Awaiting vendor patch release and specific vulnerability details.
cpes:
  - cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10:21h2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10:22h2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11:24h2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11:25h2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11:26h1:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_server_2012:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NHH9905-CVE-2026-62735&utm_source=rss&utm_medium=rss
tags:
  - cve
  - privilege-escalation
  - windows
  - kernel
vendors:
  - Microsoft
products:
  - Windows
  - Windows 10 (Version 1607, 1809, 21H2, 22H2)
  - Windows 11 (Version 23H2, 24H2, 25H2, 26H1)
  - Windows Server
  - Windows Server 2012
  - Windows Server 2012 R2
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
  - Windows Server 2025
product_versions:
  - product: Windows Server 2012
    range: '>= 6.2.9200.0, < 6.2.9200.26280'
  - product: Windows Server 2012 R2
    range: '>= 6.3.9600.0, < 6.3.9600.23338'
  - product: Windows Server 2016
    range: '>= 10.0.14393.0, < 10.0.14393.9418'
  - product: Windows Server 2019
    range: '>= 10.0.17763.0, < 10.0.17763.9121'
  - product: Windows Server 2022
    range: '>= 10.0.20348.0, < 10.0.20348.5499'
  - product: Windows Server 2025
    range: '>= 10.0.26100.0, < 10.0.26100.33296'
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2012
  - Windows Server 2012 R2
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
  - Windows Server 2025
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker with low-level privileges can trigger this overflow to cause a heap overflow in the nonpaged pool, potentially leading to privilege escalation and a SYSTEM shell.
    confidence_band: high
cves:
  - id: CVE-2026-62735
    cvss: 7.8
    epss: 0.00866
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2024-1579
  - https://cveawg.mitre.org/api/cve/CVE-2026-62735
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NHH9905-CVE-2026-62735
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NHH9905-CVE-2026-62735&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all Windows and Windows Server assets to prepare for patching
      owner: IT Operations
      due: 48h
      evidence: Source identifies multiple vulnerabilities in Windows and Windows Server.
    - action: Deploy latest Microsoft security updates to mitigate CVE-2026-62735.
      owner: IT Operations
      due: 48h
      evidence: The flaw is an exploitable kernel-level integer overflow in http.sys.
  hunt_leads:
    - lead: Monitor for anomalous system process behavior, unexpected privilege elevation events, or unauthorized file modifications on Windows servers
      data_needed:
        - Windows Event Logs (System, Security)
        - EDR telemetry
      priority: medium
      confidence: low
      disposition: hunt_now
      evidence: Source notes potential for privilege escalation, arbitrary code execution, and file manipulation.
    - lead: Monitor system event logs for Windows Bugcheck 0x50 involving the http.sys driver.
      technique_id: T1068
      data_needed:
        - System event logs
        - Kernel crash dumps
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Public PoC triggers a system crash (Bugcheck 0x50) in http.sys.
  mitigation_plan:
    - priority: immediate
      action: Apply forthcoming Microsoft security updates as soon as they become available
      owner: IT Operations
      addresses: General Windows/Windows Server vulnerabilities
      evidence: Standard remediation for security vulnerabilities affecting OS platforms.
    - priority: immediate
      action: Apply vendor-provided patches for all listed Windows versions.
      owner: IT Operations
      addresses: CVE-2026-62735
      evidence: Exploit is publicly available.
updates:
  - at: "2026-11-20T01:34:59Z"
    level: L2
    summary: added coverage for Windows 10 (Version 1607, 1809, 21H2, 22H2) +7 products
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NHH9905-CVE-2026-62735&utm_source=rss&utm_medium=rss
---

## Overview
CVE-2026-62735 is an integer overflow vulnerability in the Windows kernel driver http.sys, specifically within the UlpCreateInternalResponseOld function. The flaw occurs when calculating the total number of header bytes, leading to an incorrect allocation size that enables a heap overflow in the nonpaged pool. An attacker with low-level privileges can exploit this to achieve arbitrary code execution at SYSTEM privilege levels. This vulnerability was demonstrated at Pwn2Own Berlin 2026 and currently has public proof-of-concept code capable of triggering a system crash (Bugcheck 0x50).

## Attack Chain
1. Attacker establishes low-privilege access to the target Windows system.
2. Attacker invokes the HTTP.sys driver interface via DeviceIoControl.
3. Attacker triggers the UlpCreateInternalResponseOld function with malformed header parameters.
4. Integer overflow occurs in the TotalHeaderBytes calculation due to the provided header counts.
5. The driver performs a heap allocation based on the overflowed size in the nonpaged pool.
6. Attacker exploits the resulting heap overflow to overwrite adjacent kernel memory.
7. Attacker gains SYSTEM-level code execution.

## Impact
Successful exploitation results in a kernel-level heap overflow, which can lead to a system crash (denial of service) or full privilege escalation to the SYSTEM account.

## Recommendation
- Prioritize patching all affected Windows workstations and servers with the latest security updates provided by Microsoft.
- Monitor system logs for frequent 0x50 Bugcheck (Page Fault in Nonpaged Area) errors involving http.sys, which may indicate exploitation attempts.
- Restrict local user access to the extent possible to limit the number of users capable of interacting with vulnerable driver IOCTLs.
