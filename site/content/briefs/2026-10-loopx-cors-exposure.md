---
title: LoopX serve-status CORS Misconfiguration and Information Disclosure
slug: 2026-10-loopx-cors-exposure
description: LoopX serve-status (v0.0.1 to v0.4.4) uses a permissive wildcard CORS policy on unauthenticated local HTTP endpoints, allowing any website to exfiltrate private control-plane state and markdown documentation from local developer environments.
date: "2026-10-19T20:10:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:loopx:loopx:*:*:*:*:*:*:*:*
tags:
  - info-disclosure
  - cors
  - loopx
  - cve-2026-108372
vendors:
  - LoopX
products:
  - loopx (>= 0.0.1, < 0.4.5)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: An attacker can exploit this via a malicious website to perform zero-interaction cross-origin requests to the local machine, allowing the exfiltration of sensitive control-plane state.
    confidence_band: high
cves:
  - id: CVE-2026-108372
    epss: 0.00223
references:
  - https://github.com/advisories/GHSA-vx2m-gpq4-8j5q
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all instances of loopx to 0.4.5 or later
      owner: IT Operations
      due: 24h
      evidence: Source advises version 0.4.5 contains the fix for CORS misconfiguration.
  mitigation_plan:
    - priority: immediate
      action: Apply host firewall rules to restrict LoopX ports 8765/8766 to localhost/127.0.0.1
      owner: IT Operations
      addresses: CVE-2026-108372
      evidence: Restricting binding or access prevents foreign origin access.
---

LoopX versions prior to 0.4.5 contain a security vulnerability in the `serve-status` component where the HTTP server issues an `Access-Control-Allow-Origin: *` header on all responses, including sensitive read-only endpoints. Because the service binds to well-known local ports (8765 and 8766) and is frequently configured to run persistently as a background agent via `launchd` on macOS or equivalent startup mechanisms on other platforms, it creates a persistent, machine-wide attack surface. 

An attacker can leverage this misconfiguration by enticing a user to visit a malicious website, which then issues unauthorized cross-origin `fetch()` requests to `localhost`. This allows the attacker to read the `status.json` file (revealing project paths and task history) and fetch the content of any `.md` or `.markdown` file within the registered goal repositories. While write endpoints are protected by appropriate origin checks, the read surface is sufficient to exfiltrate private design notes, handoff documentation, and environment context without user interaction or authentication.

## Attack Chain

1. The user installs and runs `loopx serve-status` as a persistent background service (e.g., via `scripts/macos-dashboard-launchagent.sh`), binding the service to `127.0.0.1:8766`.
2. The attacker hosts a malicious website containing a cross-origin `fetch()` script targeting `http://127.0.0.1:8766/status.json`.
3. The victim opens the attacker-controlled website in their local browser.
4. The browser automatically executes the malicious script, which makes an unauthenticated GET request to the local LoopX service.
5. The LoopX service returns the JSON status payload along with the header `Access-Control-Allow-Origin: *`, which the browser accepts due to the permissive CORS policy.
6. The attacker's script parses the returned JSON to identify `goal_id`s and local repository paths.
7. The attacker's script iterates through the goal list, issuing additional GET requests to `http://127.0.0.1:8766/review-material` to exfiltrate the contents of private markdown files.

## Impact

Successful exploitation allows for the unauthorized exfiltration of sensitive information stored in developer environments. This includes project task history, local directory structures, and confidential design or handoff documentation. Because the service is often persistent and uses hardcoded default ports, the impact is sustained across user login sessions, affecting any developer running vulnerable versions of the LoopX toolset.

## Recommendation

1. Upgrade all LoopX installations to version 0.4.5 or later immediately.
2. If an immediate upgrade is not possible, restrict access to the LoopX control-plane ports (8765/8766) via host-based firewall rules to prevent cross-origin traffic originating from external browser contexts.
3. Audit local file repositories associated with LoopX for sensitive credentials or keys that may have been accessible via the `/review-material` endpoint prior to patching.
