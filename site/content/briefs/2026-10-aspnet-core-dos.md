---
title: ASP.NET Core Denial of Service via Resource Exhaustion
slug: 2026-10-aspnet-core-dos
description: A memory exhaustion vulnerability in Microsoft.AspNetCore.Localization allows unauthenticated attackers to cause unbounded memory growth and denial of service in ASP.NET Core applications.
date: "2026-10-14T00:32:36Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Microsoft
products:
  - Microsoft.AspNetCore.App.Runtime.linux-arm
  - Microsoft.AspNetCore.App.Runtime.linux-arm64
  - Microsoft.AspNetCore.App.Runtime.linux-musl-arm
  - Microsoft.AspNetCore.App.Runtime.linux-musl-arm64
  - Microsoft.AspNetCore.App.Runtime.linux-musl-x64
  - Microsoft.AspNetCore.App.Runtime.linux-x64
  - Microsoft.AspNetCore.App.Runtime.osx-arm64
  - Microsoft.AspNetCore.App.Runtime.osx-x64
  - Microsoft.AspNetCore.App.Runtime.win-arm
  - Microsoft.AspNetCore.App.Runtime.win-arm64
  - Microsoft.AspNetCore.App.Runtime.win-x64
  - Microsoft.AspNetCore.App.Runtime.win-x86
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can supply synthetic culture names that are added to the runtime's global cache, causing unbounded memory growth and leading to a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-96236
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-f4g7-52wc-p8x7
  - https://github.com/dotnet/announcements/issues/484
  - https://www.cve.org/CVERecord?id=CVE-2026-96236
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Audit environment for affected .NET versions using 'dotnet --info'
      owner: IT Operations
      due: 24h
      evidence: Advisory instructs to list versions installed via 'dotnet --info'.
  mitigation_plan:
    - priority: immediate
      action: Upgrade .NET SDK and Runtime to patched versions (e.g., 8.0.32, 9.0.21, 10.0.13, 11.0.0-rc.2)
      owner: IT Operations
      addresses: CVE-2026-96236
      evidence: Advisory provides patched versions for each runtime series.
---

Microsoft has disclosed a high-severity denial-of-service (DoS) vulnerability (CVE-2026-96236) impacting the Microsoft.AspNetCore.Localization component within ASP.NET Core. The vulnerability stems from improper handling of request-localization fallbacks, where the application cache fails to limit the registration of synthetic culture names supplied by unauthenticated users. 

An attacker can repeatedly send crafted requests containing arbitrary, synthetic culture strings to the application. Because these strings are added to the runtime's global cache without adequate throttling or capacity limits, the process memory usage grows indefinitely. This unbounded consumption eventually leads to an out-of-memory (OOM) condition, causing the service to crash or become unresponsive. This flaw affects multiple .NET versions, including 8.0, 9.0, 10.0, and 11.0 previews. Defenders must prioritize patching the .NET SDK and runtime to the specified security versions to mitigate this risk.

## Impact

Successful exploitation results in a complete denial of service for affected web applications due to memory exhaustion. The vulnerability is exploitable by unauthenticated remote attackers, making internet-facing ASP.NET Core services highly susceptible to disruption. There are no reports of data exfiltration or arbitrary code execution; however, the ease of triggering memory growth poses a significant risk to availability across all environments (Windows, Linux, and macOS).

## Recommendation

* Update all affected ASP.NET Core applications to the patched runtime versions: 8.0.32, 9.0.21, 10.0.13, or 11.0.0-rc.2.
* For self-contained deployments, recompile and redeploy the applications after updating the SDK references to ensure the patch is included in the application bundle.
* Use the `dotnet --info` command to audit installed runtimes and identify applications requiring maintenance.
* Implement request rate limiting at the web server or load balancer level to mitigate potential automated attempts to exhaust memory until patching can be completed.
