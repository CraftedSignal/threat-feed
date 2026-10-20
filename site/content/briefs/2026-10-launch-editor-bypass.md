---
brief_id: brief-2026-10-20-launch-editor-bypass
event_id: brief-2026-10-20-launch-editor-bypass
revision: 1
activity_at: "2026-10-20T23:55:54Z"
title: 'launch-editor: Windows existence check bypass leading to command injection (CVE-2026-112942)'
slug: 2026-10-launch-editor-bypass
description: An existence check bypass in launch-editor on Windows allows attackers to execute arbitrary commands by supplying crafted file paths ending in ..:line:column.
date: "2026-10-20T23:55:54Z"
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
  - cpe:2.3:a:vitejs:vite:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - command-injection
  - development-tools
vendors:
  - Vite
  - launch-editor
products:
  - launch-editor (<= 2.14.1)
  - vite (<= 6.4.3, 7.0.0-7.3.6, 8.0.0-8.1.5, 8.2.0-8.2.3, 8.3.0-8.3.2)
  - vite-plus (<= 1.0.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: The bypass allows an attacker to inject arbitrary commands into the editor command execution process, leading to OS command injection when user-controlled input is processed by the middleware.
    confidence_band: high
cves:
  - id: CVE-2026-112942
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-587h-7wmj-h5pm
  - https://github.com/vitejs/launch-editor/security/advisories/GHSA-698v-4r3x-3vcv
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch launch-editor to 2.14.2 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-112942
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected packages to the fixed versions specified in the brief
      owner: IT Operations
      addresses: CVE-2026-112942
      evidence: Source advisory
---

The `launch-editor` package, which is a dependency for Vite and related tools, contains a high-severity vulnerability identified as CVE-2026-112942. The vulnerability allows an attacker to bypass the `fs.existsSync()` check on Windows by appending a crafted suffix, `..:line:column`, to a file path. Under normal conditions, `launch-editor` validates that a target file exists before attempting to open it in an IDE or editor. However, the path manipulation vulnerability results in the validation logic incorrectly evaluating the path as a valid directory, allowing the subsequent execution of an editor command with attacker-controlled arguments.

When combined with secondary vulnerabilities involving improper character escaping (noted in GHSA-698v-4r3x-3vcv), this bypass facilitates OS command injection. This issue affects various versions of `vite`, `vite-plus`, and the standalone `launch-editor` package. Developers and security teams should prioritize patching these dependencies to prevent potential remote code execution in development environments.

## Attack Chain

1. An attacker identifies a web application or development environment utilizing a vulnerable version of `launch-editor` on a Windows host.
2. The attacker crafts a malicious request parameter containing a file path string ending in `\\..:1:1` or a similar variant.
3. The `launch-editor-middleware` processes the input and calls `path.resolve()`, treating the path as legitimate due to the suffix structure.
4. The `launch-editor` component strips the line and column suffixes, leaving a trailing `\\..` path segment.
5. The Windows `fs.existsSync()` function validates the path as existing, successfully passing the internal security check.
6. The `launch-editor` component proceeds to construct a system shell command including the user-controlled filename.
7. The system shell executes the command, resulting in OS command injection if malicious characters were successfully passed through the process invocation.

## Impact

The vulnerability poses a significant risk to developers and systems running affected Vite-based applications on Windows. Successful exploitation results in arbitrary OS command execution, potentially leading to unauthorized data access, environment compromise, or further lateral movement within a network. Numerous versions across the `vite` ecosystem are affected, including major releases from 6.x through 8.x.

## Recommendation

* Update `vite` to a non-vulnerable version (versions > 8.3.2, 8.2.3, 8.1.5, 7.3.6, or 6.4.3).
* Update `launch-editor` to versions > 2.14.1.
* Update `vite-plus` to versions > 1.0.0.
* Audit logs for suspicious file system paths ending in `..:*` or similar patterns being passed to developer tooling processes.
* Monitor for unexpected child processes spawned by Node.js or development server processes.
