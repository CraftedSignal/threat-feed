---
title: Remote Code Execution in Windows Presentation Foundation
slug: 2026-09-dotnet-wpf-rce
description: A high-severity remote code execution vulnerability (CVE-2026-50646) in .NET WPF allows arbitrary code execution via maliciously crafted XAML input.
date: "2026-09-08T21:53:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:.net_framework:4.8:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:.net_framework:4.6.2:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:.net_framework:4.7:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:.net_framework:4.7.1:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:.net_framework:4.7.2:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:.net_framework:3.5:-:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:.net_framework:4.8.1:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:visual_studio_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:visual_studio_2026:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - dotnet
  - wpf
vendors:
  - Microsoft
products:
  - Microsoft.WindowsDesktop.App.Runtime.win-arm64 (>= 10.0.0, <= 10.0.9)
  - Microsoft.WindowsDesktop.App.Runtime.win-x64 (>= 10.0.0, <= 10.0.9)
  - Microsoft.WindowsDesktop.App.Runtime.win-x86 (>= 10.0.0, <= 10.0.9)
  - Microsoft.WindowsDesktop.App.Runtime.win-arm64 (>= 9.0.0, <= 9.0.17)
  - Microsoft.WindowsDesktop.App.Runtime.win-x64 (>= 9.0.0, <= 9.0.17)
  - Microsoft.WindowsDesktop.App.Runtime.win-x86 (>= 9.0.0, <= 9.0.17)
  - Microsoft.WindowsDesktop.App.Runtime.win-arm64 (>= 8.0.0, <= 8.0.28)
  - Microsoft.WindowsDesktop.App.Runtime.win-x64 (>= 8.0.0, <= 8.0.28)
  - Microsoft.WindowsDesktop.App.Runtime.win-x86 (>= 8.0.0, <= 8.0.28)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: An attacker who successfully exploits this vulnerability could execute arbitrary code in the context of the current user.
    confidence_band: high
cves:
  - id: CVE-2026-50646
    cvss: 7.8
    epss: 0.00969
references:
  - https://github.com/advisories/GHSA-gh2h-rhph-h37g
  - https://www.cve.org/CVERecord?id=CVE-2026-50646
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Deploy patched .NET runtimes (8.0.29, 9.0.18, 10.0.10) to all production hosts
      owner: IT Operations
      due: 48h
      evidence: Advisory mandates patching to remediate CVE-2026-50646
  mitigation_plan:
    - priority: immediate
      action: Recompile and redeploy all self-contained applications with the patched runtime versions
      owner: Development
      addresses: CVE-2026-50646
      evidence: Advisory requirement for self-contained deployments
---

Microsoft has disclosed a remote code execution vulnerability (CVE-2026-50646) affecting the Windows Presentation Foundation (WPF) framework within .NET 8, .NET 9, and .NET 10. The vulnerability stems from an improper protection mechanism (CWE-693) during the parsing of XAML input. An attacker capable of delivering specially crafted XAML data to a vulnerable application can achieve arbitrary code execution in the context of the current user. This vulnerability impacts all architectures on Windows. Developers are required to update to the patched runtime versions and recompile any self-contained applications to remediate the risk.

## Impact

Successful exploitation allows an unauthenticated attacker to execute code as the user running the application, potentially leading to full system compromise or sensitive data exfiltration. The vulnerability affects a wide range of .NET desktop runtime versions, necessitating comprehensive patching across enterprise .NET environments.

## Recommendation

* Update all .NET environments to the latest runtime versions: .NET 8.0.29, .NET 9.0.18, or .NET 10.0.10.
* For applications deployed as self-contained bundles, recompile and redeploy all instances using the patched runtime.
* Use the `dotnet --info` command across endpoints to inventory and identify instances of vulnerable .NET SDKs and runtimes.
* Audit applications that accept user-provided XAML input for potential exposure to untrusted data sources.
