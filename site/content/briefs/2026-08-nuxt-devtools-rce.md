---
brief_id: brief-2026-08-05-nuxt-devtools-rce
event_id: brief-2026-08-05-nuxt-devtools-rce
revision: 2
activity_at: "2026-11-20T03:17:15Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:17:15Z"
    checksum: sha256:bb668a4ca53fd37b0db858ce855995a37bb751d9c5f2f52825b0dbc938250fbd
    summary: poc_available
    changed_fields:
      - affected_vendors
      - cpes
      - cve_verification
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - rules
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=3186A0D1-8C78-5954-B759-205A7996EDA7&utm_source=rss&utm_medium=rss
title: Unauthenticated RCE in Nuxt DevTools via Vite HMR WebSocket
slug: 2026-08-nuxt-devtools-rce
description: An unauthenticated RPC vulnerability in Nuxt DevTools (CVE-2026-71319) allows local or remote attackers to achieve arbitrary command execution by chaining malicious configuration updates and editor launch commands.
date: "2026-08-06T03:25:48Z"
lastmod: "2026-11-20T03:16:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:nuxt:devtools:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=3186A0D1-8C78-5954-B759-205A7996EDA7&utm_source=rss&utm_medium=rss
vendors:
  - Nuxt
products:
  - Nuxt DevTools
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: An attacker who can reach the HMR port can therefore chain updateOptions and openInEditor to execute an arbitrary program on the developer's machine.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204.002
    technique_name: Malicious File
    evidence: or by a malicious website the developer visits while the dev server is running (a browser can open the HMR WebSocket cross-origin).
    confidence_band: high
cve_verification:
  CVE-2026-71319:
    status: verified
    source: nvd
    checked_at: 2026-11-20T03:16:14.165978517Z
cves:
  - id: CVE-2026-71319
    cvss: 9.6
    epss: 0.00629
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-279x-mwfv-vcqv
  - https://www.npmjs.com/package/launch-editor
  - https://sploitus.com/exploit?id=3186A0D1-8C78-5954-B759-205A7996EDA7&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update @nuxt/devtools to 3.3.1
      owner: IT Operations
      due: 24h
      evidence: Fixed in @nuxt/devtools@3.3.1
  hunt_leads:
    - lead: Search for Node.js parent processes spawning shells
      technique_id: T1059.003
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: The exploit spawns child processes via launch-editor
  mitigation_plan:
    - priority: immediate
      action: Disable DevTools in config
      owner: IT Operations
      addresses: CVE-2026-71319
      evidence: 'Disable DevTools entirely with devtools: { enabled: false } in nuxt.config'
updates:
  - at: "2026-11-20T03:16:14Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=3186A0D1-8C78-5954-B759-205A7996EDA7&utm_source=rss&utm_medium=rss
---

## Overview

Nuxt DevTools version 3.x prior to 3.3.1 contains a critical vulnerability (CVE-2026-71319) in its RPC mechanism. The DevTools plugin exposes a bidirectional RPC channel over the Vite HMR WebSocket. This channel lacks authentication, meaning any client capable of reaching the HMR endpoint can issue RPC calls without a handshake or origin verification.

The vulnerability exists because specific methods - specifically `updateOptions()` and `openInEditor()` - fail to enforce authentication tokens. An attacker can use `updateOptions()` to modify the editor configuration to contain an arbitrary command. Subsequently, calling `openInEditor()` triggers the `launch-editor` package, which executes the attacker-supplied command as a child process. While Nuxt production builds are unaffected, developers running `nuxi dev` - particularly when bound to non-loopback interfaces or when the developer interacts with a malicious website that initiates a cross-origin WebSocket connection - are at significant risk of local command execution.

## Attack Chain

1. Attacker identifies a developer running Nuxt DevTools on a reachable port (e.g., 3000) via local network or browser-based cross-origin request.
2. Attacker establishes a WebSocket connection to the Vite HMR endpoint (`ws://<host>:<port>/`).
3. Attacker sends a malformed `nuxt:devtools:rpc` payload to the `updateOptions` method.
4. The payload injects a malicious command string into the `behavior.openInEditor` configuration key within the session memory.
5. Attacker sends a follow-up RPC call to `openInEditor`, specifying a file path to trigger the execution logic.
6. The `launch-editor` package receives the modified configuration and spawns the malicious command as a child process on the developer's host machine.
7. Final objective: Achieve arbitrary code execution on the developer's workstation with their current user privileges.

## Impact

Successful exploitation results in full remote code execution on the developer's host. This compromises the development environment, potentially allowing the attacker to steal source code, access environment variables, or establish persistent backdoors into the developer's workstation. The scope is limited to development environments, but impacts anyone using affected versions of `@nuxt/devtools`.

## Recommendation

- Update `@nuxt/devtools` to version 3.3.1 or higher across all development projects to remediate CVE-2026-71319.
- Audit existing projects for the use of the `--host` flag in `nuxi dev`, as this increases the attack surface to network-based threats.
- Disable DevTools in `nuxt.config` if it is not required for active debugging.
- Deploy the provided Sigma rule to detect suspicious WebSocket connection patterns or atypical child process spawns initiated by the Node.js process running the development server.
