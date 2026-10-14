---
title: Denial of Service Vulnerability in .NET XML Components
slug: 2026-10-net-xml-dos
description: A denial-of-service vulnerability (CVE-2026-58280) in Microsoft .NET's System.Security.Cryptography.Xml and System.Private.Xml components allows attackers to crash applications via uncontrolled recursion and resource exhaustion.
date: "2026-10-14T00:33:03Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - vulnerability
  - denial-of-service
  - dotnet
  - cve-2026-58280
vendors:
  - Microsoft
products:
  - Microsoft.NETCore.App.Runtime.linux-arm (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.linux-arm64 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.linux-musl-arm (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.linux-musl-arm64
  - Microsoft.NETCore.App.Runtime.linux-musl-x64 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.linux-x64 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.osx-arm64 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.osx-x64 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.win-arm (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.win-arm64 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.win-x64 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
  - Microsoft.NETCore.App.Runtime.win-x86 (8.0.0-8.0.31, 9.0.0-9.0.20, 10.0.0-10.0.12, 11.0.0-preview.1-11.0.0-rc.1)
cves:
  - id: CVE-2026-58280
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-mc4q-93x5-f6hj
  - https://github.com/dotnet/announcements/issues/447
  - https://www.cve.org/CVERecord?id=CVE-2026-58280
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade all .NET runtimes to patched versions (8.0.32, 9.0.21, 10.0.13, 11.0.0-rc.2).
      owner: IT Operations
      due: 48h
      evidence: Advisory instructions for remediation
  mitigation_plan:
    - priority: immediate
      action: Recompile and redeploy all self-contained applications using identified vulnerable runtime versions.
      owner: IT Operations
      addresses: CVE-2026-58280
      evidence: Microsoft advisory guidance on self-contained deployments
---

Microsoft has disclosed a high-severity denial-of-service (DoS) vulnerability, tracked as CVE-2026-58280, affecting the System.Security.Cryptography.Xml and System.Private.Xml components within Microsoft .NET. The vulnerability, classified as CWE-674 (Uncontrolled Recursion), allows an unauthenticated attacker to cause excessive resource consumption and application crashes by supplying specially crafted XML inputs to vulnerable services. 

The flaw exists in how the affected components handle XML processing, specifically related to entity references, DTD processing, and C14N transforms. By sending inputs designed to trigger deep recursion or inflate operation counts, an attacker can effectively disable services relying on these .NET libraries. Microsoft has addressed this in the latest .NET SDK and runtime releases by implementing stricter depth and operation count limits, disabling DTD processing by default, and validating entity references. Defenders must ensure all deployed .NET applications, including self-contained deployments, are updated to the patched versions to mitigate this risk.

## Impact

Successful exploitation results in a denial-of-service condition, rendering affected .NET-based applications or services unresponsive. The vulnerability is network-exploitable, requires no authentication, and impacts a wide range of .NET versions (8.0, 9.0, 10.0, and 11.0-preview branches) across Windows, Linux, and macOS platforms. Given the ubiquity of .NET in enterprise backend services and public-facing APIs, this vulnerability poses a significant risk to service availability if left unpatched.

## Recommendation

- Update all .NET environments to the latest runtime versions: 8.0.32, 9.0.21, 10.0.13, or 11.0.0-rc.2.
- Recompile and redeploy all self-contained applications targeting any of the impacted versions listed in the advisory.
- Use the 'dotnet --info' command to audit currently installed versions across all development and production servers.
- Monitor application logs for spikes in CPU usage or unexpected process terminations associated with XML parsing operations, which may indicate exploitation attempts.
