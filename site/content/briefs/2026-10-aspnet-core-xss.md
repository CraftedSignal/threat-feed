---
title: CVE-2026-96230 ASP.NET Core Cross-Site Scripting Vulnerability
slug: 2026-10-aspnet-core-xss
description: An unencoded exception reflection vulnerability in the Blazor WebAssembly development server allows remote attackers to perform cross-site scripting (XSS) via the unauthenticated /_framework/debug endpoint.
date: "2026-10-14T00:30:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:microsoft_aspnetcore_components_webassembly_server:*:*:*:*:*:*:*:*
tags:
  - xss
  - dot-net
  - web-application
  - cve-2026-96230
vendors:
  - Microsoft
products:
  - Microsoft.AspNetCore.Components.WebAssembly.Server (>= 8.0.0, <= 8.0.31)
  - Microsoft.AspNetCore.Components.WebAssembly.Server (>= 9.0.0, <= 9.0.20)
  - Microsoft.AspNetCore.Components.WebAssembly.Server (>= 10.0.0, <= 10.0.12)
  - Microsoft.AspNetCore.Components.WebAssembly.Server (>= 11.0.0-preview.1, <= 11.0.0-rc.1)
affected_os:
  - Windows
  - Linux
  - macOS
cves:
  - id: CVE-2026-96230
    cvss: 8.8
references:
  - https://github.com/advisories/GHSA-qjpx-jqm5-h2c4
  - https://github.com/dotnet/announcements/issues/478
  - https://www.cve.org/CVERecord?id=CVE-2026-96230
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update Microsoft.AspNetCore.Components.WebAssembly.Server package references to patched versions
      owner: Application Security
      due: 48h
      evidence: Source provides specific patched versions for 8.0, 9.0, 10.0, and 11.0-preview branches
  mitigation_plan:
    - priority: immediate
      action: Upgrade .NET SDK and runtime, recompile self-contained deployments
      owner: IT Operations
      addresses: CVE-2026-96230
      evidence: Advisory recommends updating SDKs and recompiling self-contained apps
---

Microsoft has disclosed a high-severity cross-site scripting (XSS) vulnerability, tracked as CVE-2026-96230, affecting the `Microsoft.AspNetCore.Components.WebAssembly.Server` package. This vulnerability exists within the Blazor WebAssembly development server debug functionality. When the `dotnet watch` command is utilized for development, the server exposes an unauthenticated `/_framework/debug` endpoint. This endpoint fails to properly encode exception text, allowing an attacker to reflect malicious scripts through the debug page. 

This issue is particularly relevant to environments where developers are actively using the `dotnet watch` tooling. If exploited, an attacker could inject scripts into the session of a user viewing the development server interface. Organizations should identify projects utilizing the affected versions of `Microsoft.AspNetCore.Components.WebAssembly.Server` across Windows, Linux, and macOS environments and update to the patched releases immediately.

## Impact

The vulnerability is categorized with a CVSS 3.1 score of 8.8 (High). Successful exploitation allows an attacker to execute arbitrary scripts in the context of the user's browser, potentially leading to unauthorized data access, session hijacking, or further client-side exploitation. This risk is localized to development environments where the `dotnet watch` command is active.

## Recommendation

* Identify and update all .NET projects referencing the vulnerable `Microsoft.AspNetCore.Components.WebAssembly.Server` package to the following versions:
 * 8.0.32
 * 9.0.21
 * 10.0.13
 * 11.0.0-rc.2
* Update the .NET SDK and runtime by installing the latest versions available from Microsoft.
* Recompile and redeploy any self-contained applications that were built using the affected versions of the package.
* Restrict access to development-server endpoints in network environments, ensuring they are not exposed to untrusted users or external networks.
