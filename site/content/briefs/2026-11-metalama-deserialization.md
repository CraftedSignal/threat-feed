---
brief_id: brief-2026-11-04-metalama-deserialization
event_id: brief-2026-11-04-metalama-deserialization
revision: 1
activity_at: "2026-11-04T04:13:40Z"
title: 'PostSharp Metalama: Unsafe deserialization in Visual Studio named pipes (CVE-2026-62848)'
slug: 2026-11-metalama-deserialization
description: Metalama's Visual Studio integration is vulnerable to arbitrary code execution due to unsafe deserialization of inter-process communication messages via predictable named pipes, requiring local access as the same user.
date: "2026-11-04T04:13:40Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:postsharp:metalama.framework:*:*:*:*:*:*:*:*
vendors:
  - PostSharp
products:
  - Metalama.Framework (< 2026.1.19)
  - PostSharpTechnologies.PostSharp (2024.1 - 2026.1.4)
  - PostSharpTechnologies.Metalama (all versions)
  - PostSharpTechnologies.caravela (all versions)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: A local process able to write to the pipe can send a crafted message that instantiates arbitrary .NET types — a deserialization primitive in the same class as BinaryFormatter (CWE-502), and a well-known gadget-chain code-execution vector.
    confidence_band: high
cves:
  - id: CVE-2026-62848
    cvss: 7.3
    epss: 0.00186
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-h26j-4vp7-x9w2
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62848
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all developer workstations running PostSharp or Metalama VS extensions.
      owner: IT Operations
      due: 48h
      evidence: Advisory lists affected product versions requiring remediation.
  hunt_leads:
    - lead: Monitor for processes creating named pipes following the pattern 'Metalama_*' and investigate unexpected processes writing to these pipes.
      technique_id: T1059
      data_needed:
        - Sysmon Event ID 17/18 (Pipe Created/Connected)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: 'The pipe name is predictable: Metalama_{role}_{processId}_{hash(PackageVersion)}.'
  mitigation_plan:
    - priority: immediate
      action: Upgrade Metalama.Framework to 2026.1.19 and update PostSharp extension to 2026.1.5.
      owner: IT Operations
      addresses: CVE-2026-62848
      evidence: Fix provided in Metalama 2026.1.19 and PostSharp extension 2026.1.5.
---

Metalama's Visual Studio integration utilizes inter-process communication (IPC) via local Windows named pipes to exchange data between the Visual Studio UI process (`devenv`), Roslyn analysis processes, and CodeLens. These pipes perform unsafe deserialization of incoming messages without an allow-list, enabling arbitrary .NET type instantiation. 

The vulnerability manifests through two primary deserialization mechanisms: 
1. Newtonsoft.Json with `TypeNameHandling.All` (Metalama 2023.0 through 2026.0.x).
2. Typeless MessagePack (Metalama 2026.1.0 through 2026.1.18).

Both mechanisms leverage predictable pipe names (`Metalama_{role}_{processId}_{hash(PackageVersion)}`). Because the pipe access is restricted to the same logged-in user via default Windows ACLs, successful exploitation allows an attacker already executing code under the developer's context to achieve code execution within the Visual Studio process.

## Impact

Successful exploitation results in arbitrary code execution within the Visual Studio UI, Roslyn analysis, or CodeLens processes. This grants the attacker full control over the process context, including the ability to access data and modify developer environment states, limited to the permissions of the current logged-in user.

## Recommendation

- Upgrade `Metalama.Framework` to version 2026.1.19 or later.
- Update the `PostSharpTechnologies.PostSharp` Visual Studio extension to version 2026.1.5 or later.
- Uninstall retired extensions `PostSharpTechnologies.Metalama` and `PostSharpTechnologies.caravela` and migrate to the maintained PostSharp extension (>= 2026.1.5).
- Prioritize these updates for developer workstations where the Metalama extension is active.
