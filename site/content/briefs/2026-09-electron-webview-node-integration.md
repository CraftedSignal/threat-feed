---
title: Electron WebView Node.js Integration Bypass
slug: 2026-09-electron-webview-node-integration
description: A vulnerability in the Electron framework allows a <webview> tag to enable Node.js integration within Web Workers regardless of the embedder's restricted settings, potentially leading to unauthorized code execution.
date: "2026-09-29T22:19:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openjsf:electron:*:*:*:*:*:*:*:*
vendors:
  - OpenJS Foundation
products:
  - Electron (41.10.6, 42.9.2, 43.4.1, 44.0.0-beta.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1204.002
    technique_name: User Execution
    evidence: A <webview> could enable Node.js integration in its Web Workers even when its embedder had Node.js integration disabled, giving guest content more privilege than the embedder allowed.
    confidence_band: high
cves:
  - id: CVE-2026-102676
    cvss: 8.3
references:
  - https://github.com/advisories/GHSA-9qh4-3jw8-366w
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-102676
action_plan:
  priority: elevated
  owners:
    - Application Security
    - Development Team
  immediate_actions:
    - action: Upgrade Electron packages to fixed versions 41.10.6, 42.9.2, 43.4.1, or 44.0.0-beta.5.
      owner: Development Team
      due: 72h
      evidence: Fixed versions provided by vendor advisory.
  mitigation_plan:
    - priority: immediate
      action: Remove nodeIntegrationInWorker from guest preferences in will-attach-webview handler.
      owner: Development Team
      addresses: CVE-2026-102676
      evidence: Workaround documentation from advisory.
---

The Electron framework is susceptible to a privilege escalation vulnerability (CVE-2026-102676) where a `<webview>` tag may enable Node.js integration in its associated Web Workers, even when the parent embedder has explicitly disabled Node.js integration. This flaw creates a scenario where untrusted guest content gains unauthorized access to Node.js APIs, bypassing the security boundaries established by the parent application. The vulnerability specifically impacts applications that utilize the `<webview>` tag in an unsandboxed state. The lack of proper isolation between the embedder and the guest process allows for potential sandbox escapes or cross-context code execution, as the guest worker context assumes permissions that the developer intended to restrict. Defenders should prioritize auditing Electron-based applications for the use of the `<webview>` component and ensuring that `nodeIntegrationInWorker` is correctly managed or that the `sandbox` mode is strictly enforced.

## Impact

Successful exploitation allows guest content within a `<webview>` to access privileged Node.js APIs that should have been disabled. This can lead to arbitrary code execution within the context of the guest process, potentially allowing an attacker to escape the intended sandbox and compromise the application or the underlying host system.

## Recommendation

Prioritized actions for development and security operations teams:
- Patch all applications using the affected Electron versions by updating to at least 41.10.6, 42.9.2, 43.4.1, or 44.0.0-beta.5.
- Implement a configuration audit to identify instances where the `<webview>` tag is enabled, particularly when loading untrusted remote content.
- Remove `nodeIntegrationInWorker` from guest preferences within the `will-attach-webview` handler in the application source code.
- Enforce the use of the sandbox mode for all `<webview>` components to isolate guest processes from host resources.
