---
brief_id: brief-2026-10-28-wails-origin-bypass
event_id: brief-2026-10-28-wails-origin-bypass
revision: 1
activity_at: "2026-10-28T06:02:25Z"
title: 'Wails: Origin validator bypass via wildcard pattern (CVE-2026-34157)'
slug: 2026-10-wails-origin-bypass
description: Wails v2 allows attackers to bypass BindingsAllowedOrigins restrictions via a permissive regex flaw in origin validation, potentially enabling unauthorized execution of Go backend methods.
date: "2026-10-28T06:02:25Z"
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
  validation_status: Source verified; configuration audit recommended for local environment.
cpes:
  - cpe:2.3:a:wails:wails:*:*:*:*:*:*:*:*
tags:
  - web-application
  - vulnerability
  - ipc
  - origin-bypass
vendors:
  - Wails
products:
  - wails (< 2.13.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who controls a domain sharing a prefix with the allowed origin can invoke arbitrary bound Go methods.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: 'Depending on the application: OS command execution (if exposed via bindings).'
    confidence_band: high
cves:
  - id: CVE-2026-34157
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-47hv-j4px-h3c9
  - https://github.com/wailsapp/wails/pull/5074
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34157
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit Wails application configuration files for BindingsAllowedOrigins patterns ending in an asterisk.
      owner: IT Operations
      due: 72h
      evidence: The vulnerability manifests when developers use a trailing wildcard (e.g., myapp.com*).
  hunt_leads:
    - lead: Identify Wails desktop applications in the environment and inspect source code or build configurations for the vulnerable wildcard pattern in BindingsAllowedOrigins.
      technique_id: T1190
      data_needed:
        - Application source code
        - Configuration file exports
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability occurs when wildcard patterns are appended to partial domain labels.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Wails to 2.13.0 or later.
      owner: IT Operations
      addresses: CVE-2026-34157
      evidence: 'PR #5074 fixes the wildcard expansion logic.'
---

Wails v2 contains a vulnerability in the `wildcardPatternToRegex` function within `originValidator.go`. The implementation incorrectly replaces wildcards (`*`) with unanchored regex matchers (`.*`). Developers using a trailing wildcard pattern (e.g., `myapp.com*`) in `BindingsAllowedOrigins` inadvertently create a bypass, as the regex fails to restrict matches to legitimate domain boundaries. An attacker can craft a malicious origin (e.g., `myapp.com.attacker.com` or `myapp.community`) to invoke bound Go methods, leading to unauthorized actions such as file system access or command execution. The issue is addressed in PR #5074, which restricts wildcard expansion to full domain components.

## Impact
If a Wails application exposes sensitive bindings, an attacker-controlled origin can execute those methods. Observed potential impacts include unauthorized file system read/write, credential exfiltration, and execution of OS commands if mapped to the application frontend.

## Recommendation
* Upgrade Wails to version 2.13.0 or later once released.
* Audit existing `BindingsAllowedOrigins` configurations in Wails applications. Ensure wildcard patterns are used only for full domain components (e.g., `https://*.myapp.com`) and avoid trailing wildcards on partial labels (e.g., `myapp.com*`).
* Review exposed Go methods in application bindings to ensure they follow the principle of least privilege.
