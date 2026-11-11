---
brief_id: brief-2026-11-11-microsoft-netcore-heap-overflow
event_id: brief-2026-11-11-microsoft-netcore-heap-overflow
revision: 1
activity_at: "2026-11-11T01:54:48Z"
title: 'Microsoft .NET Runtime: Heap-based buffer overflow in Microsoft.NETCore.App.Runtime.win-x86 (CVE-2026-114158)'
slug: 2026-11-microsoft-netcore-heap-overflow
description: A heap-based buffer overflow vulnerability in Microsoft.NETCore.App.Runtime.win-x86 (CVE-2026-114158) allows a remote attacker to achieve arbitrary code execution via a network-based attack vector requiring user interaction.
date: "2026-11-11T01:54:48Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Inventory check required
cpes:
  - cpe:2.3:a:microsoft:microsoft_netcore_app_runtime_win_x86:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - buffer-overflow
  - dotnet
vendors:
  - Microsoft
products:
  - Microsoft.NETCore.App.Runtime.win-x86 (>= 8.0.0, < 8.0.34)
affected_os:
  - Windows
cves:
  - id: CVE-2026-114158
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114158
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-114158
  - https://github.com/advisories/GHSA-cjjx-gv54-83qh
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory software dependencies to identify instances of Microsoft.NETCore.App.Runtime.win-x86 in the vulnerable version range.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions >= 8.0.0, < 8.0.34
  mitigation_plan:
    - priority: immediate
      action: Apply updates provided by Microsoft for CVE-2026-114158 once available
      owner: IT Operations
      addresses: CVE-2026-114158
      evidence: Official MSRC guidance
---

Microsoft has disclosed a heap-based buffer overflow vulnerability (CVE-2026-114158) impacting the Microsoft.NETCore.App.Runtime.win-x86 package. The flaw exists in versions 8.0.0 through 8.0.33. An unauthorized remote attacker could trigger this vulnerability to execute arbitrary code, though successful exploitation requires user interaction. This advisory was flagged as a duplicate of GHSA-r8h3-p8p6-ggp7 in the GitHub Advisory Database.

## Impact

Successful exploitation could result in full loss of confidentiality, integrity, and availability of the affected system, as the vulnerability allows for remote code execution.

## Recommendation

- Inventory all environments utilizing the `Microsoft.NETCore.App.Runtime.win-x86` NuGet package to identify instances within the vulnerable range (8.0.0 to 8.0.33).
- Review the Microsoft Security Update Guide for CVE-2026-114158 for guidance on the required patches or updated runtime versions once released by Microsoft.
- Prioritize systems that ingest untrusted or externally sourced network content where user interaction is common.
