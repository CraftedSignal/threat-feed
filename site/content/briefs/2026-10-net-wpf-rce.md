---
title: Microsoft .NET WPF Pixel-Shader Heap Corruption
slug: 2026-10-net-wpf-rce
description: A heap out-of-bounds vulnerability in the .NET WPF runtime allows attackers to achieve remote code execution through crafted pixel-shader bytecode.
date: "2026-10-14T00:31:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:dotnet:*:*:*:*:*:*:*:*
tags:
  - .net
  - windows
  - rce
  - heap-overflow
  - wp-vulnerability
vendors:
  - Microsoft
products:
  - Microsoft.WindowsDesktop.App.Runtime (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows for remote code execution due to heap out-of-bounds writes in the WPF pixel-shader engine.
    confidence_band: high
cves:
  - id: CVE-2026-96224
    cvss: 8.8
references:
  - https://github.com/advisories/GHSA-xq57-crx4-g373
  - https://www.cve.org/CVERecord?id=CVE-2026-96224
  - https://github.com/dotnet/announcements/issues/475
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch all .NET runtimes and SDKs to the versions specified in the advisory.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-96224 remediation guidance.
    - action: Recompile and redeploy all self-contained .NET applications.
      owner: Security Engineering
      due: 72h
      evidence: Advisory requirement for self-contained applications.
  mitigation_plan:
    - priority: immediate
      action: Upgrade .NET runtime to patched versions (8.0.32, 9.0.21, 10.0.13, 11.0.0-rc.2).
      owner: IT Operations
      addresses: CVE-2026-96224
      evidence: Microsoft Security Advisory
---

Microsoft has disclosed a critical security vulnerability, CVE-2026-96224, affecting the Windows Presentation Foundation (WPF) component within the .NET runtime. The vulnerability exists within the `CPSTrans::Initialize` function, where crafted pixel-shader bytecode can induce a desynchronization between two parsing passes. This flaw results in heap out-of-bounds read or write operations, which can be leveraged by a remote attacker to achieve arbitrary code execution on systems running vulnerable .NET applications. The issue impacts multiple versions of the .NET runtime, including .NET 8.0, 9.0, 10.0, and early versions of 11.0. Organizations are advised to update their .NET SDKs and runtime environments immediately. Furthermore, developers must recompile and redeploy self-contained applications that bundle the affected WPF components to ensure full remediation.

## Impact

Successful exploitation allows for remote code execution on the underlying host. The impact is significant for any .NET desktop application that processes untrusted visual content or pixel-shader files. Given the prevalence of .NET in enterprise desktop environments, the potential scope includes a broad range of internal and third-party tools. If exploited, an attacker could gain the same privileges as the user running the affected application, leading to data exfiltration, local persistence, or lateral movement within the environment.

## Recommendation

* Update all .NET environments to the latest patched versions: 8.0.32, 9.0.21, 10.0.13, or 11.0.0-rc.2.
* Trigger updates via Visual Studio to ensure local developer SDKs are remediated.
* Identify all self-contained deployments using `dotnet --info` and recompile these applications with the updated runtime versions to mitigate the risk of embedded vulnerable libraries.
* Monitor for abnormal crashes in .NET-based applications, as memory corruption exploits often cause instability in the host process prior to successful payload execution.
