---
title: Remote Code Execution in .NET System.Net.Sockets
slug: 2026-10-net-socket-rce
description: A high-severity remote code execution vulnerability (CVE-2026-70197) in .NET allows unauthenticated out-of-bounds writes on Windows when reusing SocketAsyncEventArgs across IPv4 and IPv6 datagram sockets.
date: "2026-10-14T00:32:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - dotnet
  - windows
vendors:
  - Microsoft
products:
  - Microsoft.NETCore.App.Runtime.win-arm (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.win-arm64 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.win-x64 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.win-x86 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
affected_os:
  - Windows
cves:
  - id: CVE-2026-70197
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-4mpw-cpwj-hxxj
  - https://github.com/dotnet/announcements/issues/466
  - https://www.cve.org/CVERecord?id=CVE-2026-70197
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch all vulnerable .NET runtime versions to the specified fixed versions (8.0.32, 9.0.21, 10.0.13, 11.0.0-rc.2).
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends immediate update of SDK and runtimes.
  mitigation_plan:
    - priority: immediate
      action: Upgrade .NET runtime to patched versions for all self-contained applications.
      owner: IT Operations
      addresses: CVE-2026-70197
      evidence: Advisory requires re-deployment of self-contained applications.
---

Microsoft has disclosed a critical memory safety vulnerability, tracked as CVE-2026-70197, affecting the System.Net.Sockets component within the .NET runtime on Windows. The vulnerability stems from improper handling of cached native address buffers when a SocketAsyncEventArgs instance is reused across different types of datagram sockets, specifically transitioning between IPv4 and IPv6. Under these conditions, the internal buffer becomes undersized, permitting an out-of-bounds write during the execution of the ReceiveFromAsync operation. This flaw allows an unauthenticated, remote attacker to trigger memory corruption, which may lead to arbitrary code execution within the context of the application utilizing the vulnerable .NET runtime. The issue impacts multiple versions of .NET, including 8.0, 9.0, 10.0, and 11.0-preview releases on all Windows architectures.

## Impact

Successful exploitation of CVE-2026-70197 could allow an unauthenticated attacker to execute arbitrary code with the privileges of the .NET application process. Given the nature of .NET applications often running as backend services or web servers, this could lead to full system compromise, data exfiltration, or lateral movement within the environment. All organizations running .NET applications on Windows should audit their environment for the impacted runtime versions and prioritize deployment of the specified patches.

## Recommendation

* Identify all vulnerable .NET applications by running `dotnet --info` on hosts to determine installed SDK and runtime versions.
* Update the .NET runtime to the patched versions (8.0.32, 9.0.21, 10.0.13, or 11.0.0-rc.2) across all development and production environments.
* Recompile and redeploy all self-contained applications that target the vulnerable runtime versions.
* Update Visual Studio to the latest version to ensure that associated .NET SDKs are correctly upgraded.
* Monitor internal network traffic for anomalous socket communication patterns associated with datagram-heavy .NET services, as these may indicate attempts to trigger the buffer state conditions required for exploitation.
