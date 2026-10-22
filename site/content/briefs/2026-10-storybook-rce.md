---
brief_id: brief-2026-10-22-storybook-rce
event_id: brief-2026-10-22-storybook-rce
revision: 1
activity_at: "2026-10-22T20:02:53Z"
title: 'Storybook: Remote code execution via local network WebSocket token theft (CVE-2026-114126)'
slug: 2026-10-storybook-rce
description: The Storybook development server exposes authentication tokens via WebSocket, allowing attackers on the same local network to inject malicious code into story files and execute arbitrary commands through vulnerable addons.
date: "2026-10-22T20:02:53Z"
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
  validation_status: Source confirmed; mitigation via version upgrade is standard for CVEs of this nature.
tags:
  - rce
  - webserver
  - storybook
  - vulnerability
vendors:
  - Storybook
products:
  - storybook (>= 8.0.0, < 8.6.19)
  - storybook (>= 9.0.0, < 9.1.21)
  - storybook (>= 10.0.0, < 10.6.2)
  - storybook (>= 11.0.0-alpha.0, < 11.0.0-alpha.6)
  - '@storybook/core (>= 8.0.0, < 8.6.19)'
  - '@storybook/core-server (>= 8.0.0, < 8.6.19)'
  - '@storybook/experimental-addon-test (>= 8.0.0, < 8.6.19)'
  - '@storybook/addon-vitest (>= 9.0.0, < 9.1.21)'
  - '@storybook/addon-vitest (>= 10.0.0, < 10.6.2)'
  - '@storybook/addon-vitest (>= 11.0.0-alpha.0, < 11.0.0-alpha.6)'
  - '@storybook/addon-mcp (>= 10.6.0, < 10.6.2)'
  - '@storybook/addon-mcp (>= 11.0.0-alpha.0, < 11.0.0-alpha.6)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker on the same local network can access the dev server, obtain the WebSocket authentication token, and use it to inject code into story files.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: Depending on the exploit content, where the file is written, and what software the developer uses, that exploit could then be executed.
    confidence_band: high
cves:
  - id: CVE-2026-114126
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-px85-f4q5-jh77
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114126
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade storybook to 8.6.19 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory requires upgrade to mitigate CVE-2026-114126.
  mitigation_plan:
    - priority: immediate
      action: Configure Storybook to bind only to loopback address (127.0.0.1).
      owner: IT Operations
      addresses: CVE-2026-114126
      evidence: Storybook now only listens on 127.0.0.1 by default in updated versions.
---

Storybook development servers are vulnerable to remote code execution (CVE-2026-114126) when accessible from an untrusted local network. An attacker can access the Storybook dev server by IP address, bypass WebSocket authentication, and interact with the server's WebSocket API. This access permits the injection of malicious code into story files or the triggering of file operations through the Vitest addon. The vulnerability is mitigated by upgrading to patched versions, which enforce stricter host binding (loopback only) and restrict dangerous filesystem/process execution APIs within the Vitest addon.

## Attack Chain
1. Attacker connects to the same local network (LAN/WiFi) as a developer running a Storybook dev server.
2. Attacker probes the local network to locate active Storybook dev server instances.
3. Attacker accesses the Storybook web UI via browser or client request, causing the browser to load the vulnerable page.
4. Attacker extracts the WebSocket authentication token exposed by the vulnerable server.
5. Attacker authenticates to the WebSocket API using the stolen token.
6. Attacker sends a malicious request to the `saveStoryRequest` event to write a payload into a story file.
7. Attacker triggers a test execution cycle via the WebSocket.
8. If the Vitest addon is installed, the injected payload leverages the addon API to write arbitrary files or execute processes on the developer machine.

## Impact
The vulnerability allows unauthorized parties to perform arbitrary file writes and execute code on developer workstations. The impact is elevated if the Vitest addon is present and configured with unrestricted filesystem or execution permissions.

## Recommendation
- Upgrade Storybook packages immediately: 11.0.0-alpha.6, 10.6.2, 9.1.21, or 8.6.19.
- Audit existing environments and ensure development servers bind only to '127.0.0.1' unless explicitly required for shared network testing.
- Restrict access to development machines using local host-based firewalls to prevent unauthorized ingress from untrusted network peers.
- Review and disable 'browser.api.allowWrite' and 'browser.api.allowExec' in Vitest configurations if these capabilities are not required for development workflows.
- Avoid using the '--host' CLI option with insecure interfaces (e.g., '0.0.0.0') on untrusted local networks.
