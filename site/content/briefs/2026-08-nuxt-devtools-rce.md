---
title: Unauthenticated RCE in Nuxt DevTools via Vite HMR WebSocket
slug: 2026-08-nuxt-devtools-rce
description: An unauthenticated RPC vulnerability in Nuxt DevTools (CVE-2026-71319) allows local or remote attackers to achieve arbitrary command execution by chaining malicious configuration updates and editor launch commands.
date: "2026-08-06T03:25:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
products:
  - Nuxt DevTools
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An attacker who can reach the HMR port can therefore chain updateOptions and openInEditor to execute an arbitrary program on the developer's machine.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204.002
    technique_name: 'User Execution: Malicious File'
    evidence: or by a malicious website the developer visits while the dev server is running (a browser can open the HMR WebSocket cross-origin).
    confidence_band: high
cves:
  - id: CVE-2026-71319
    cvss: 9.6
references:
  - https://github.com/advisories/GHSA-279x-mwfv-vcqv
  - https://www.npmjs.com/package/launch-editor
rules:
  - title: Detect Suspicious Child Process Execution from Node.js
    description: Detects potential exploitation of CVE-2026-71319 where a Node.js process spawns unexpected shell-like commands often used in launch-editor exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
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
---

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
