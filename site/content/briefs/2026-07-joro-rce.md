---
title: 'Joro: Unauthenticated Cross-Origin Plugin Upload Leads to RCE'
slug: 2026-07-joro-rce
description: Joro's default proxy mode (versions ≤ v1.1.0) is vulnerable to unauthenticated remote code execution (CVE-2026-53649) via a local API on `127.0.0.1:9090` that allows cross-origin JavaScript to upload a malicious native plugin and trigger a system restart, leading to RCE as the operator's user from a single page visit.
date: "2026-07-08T20:36:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - web-exploitation
  - vulnerability
  - javascript
  - cross-origin
  - cors
vendors:
  - BishopFox
products:
  - Joro (≤ v1.1.0)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: The operator visits an attacker-controlled page in Firefox on their machine.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Since plugins execute on load, this yields unauthenticated remote code execution as the operator's user from a single page visit.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: On restart, `plugin.Open("pwn.so")` calls `init()`, which opens a goroutine and dials back to the attacker's listener.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An interactive `/bin/bash -i` shell is obtained as the operator's user.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: JavaScript on the page fetches `pwn.so` from the attacker's server (same-origin, no CORS issue).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xqhv-chqm-fhcc
iocs:
  - type: file_name
    value: pwn.so
ioc_counts:
  file_name: 1
rules:
  - title: Detect CVE-2026-53649 Exploitation - Joro Plugin Upload
    description: Detects exploitation attempts of CVE-2026-53649 by monitoring for unauthenticated POST requests to Joro's plugin upload endpoint, indicative of a malicious plugin upload.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1189
      - T1203
    data_sources:
      - webserver
  - title: Detect CVE-2026-53649 Exploitation - Joro System Restart
    description: Detects exploitation attempts of CVE-2026-53649 by monitoring for unauthenticated POST requests to Joro's system restart endpoint, indicating a trigger for execution of an uploaded malicious plugin.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
      - T1574.002
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability (CVE-2026-53649) affects BishopFox Joro versions ≤ v1.1.0 when running in its default proxy mode. An attacker can achieve unauthenticated remote code execution (RCE) on an operator's workstation (Linux/macOS) by leveraging a combination of weaknesses. Joro exposes a local API on `127.0.0.1:9090` which lacks authentication and applies a wildcard CORS policy. This design flaw allows cross-origin JavaScript on any attacker-controlled webpage to POST `multipart/form-data` requests directly to privileged API endpoints, such as `/api/v1/plugins/upload` and `/api/v1/system/restart`, through the victim's browser. Since Joro plugins execute their `init()` functions upon loading, this mechanism allows for an unauthenticated RCE as the operator's user with a single page visit. The vulnerability was reported on 2026-05-27 and an advisory published on 2026-07-08.

## Attack Chain

1. The operator visits an attacker-controlled web page in their browser (e.g., Firefox).
2. JavaScript embedded in the attacker's page fetches a malicious shared object (`pwn.so`) from the attacker's server.
3. The JavaScript then POSTs the `pwn.so` file to the local Joro API endpoint `http://127.0.0.1:9090/api/v1/plugins/upload` as `multipart/form-data`. Joro accepts this request due to the lack of authentication and permissive CORS policy.
4. Immediately following, the JavaScript POSTs a request to `http://127.0.0.1:9090/api/v1/system/restart`, instructing Joro to re-execute.
5. Upon restart, Joro attempts to open the newly uploaded `pwn.so` plugin. During the `plugin.Open()` call, the plugin's `init()` function is executed before any symbol lookup.
6. The malicious `init()` function initiates a connection back to the attacker's listener, granting the attacker an interactive `/bin/bash -i` shell as the operator's user.

## Impact

This vulnerability leads to unauthenticated, remote, browser-mediated code execution as the operator's user on affected Linux and macOS systems. The exploit pivots through the victim's browser to the loopback-bound Joro API, effectively bypassing network isolation typically assumed for `127.0.0.1` services. A single malicious `.so` plugin can be crafted to work against all operators running the affected Joro release, enabling widespread compromise of Joro users. The impact is direct system compromise and full control over the operator's user context.

## Recommendation

* Upgrade BishopFox Joro to a version greater than v1.1.0 immediately to patch CVE-2026-53649. Specifically, ensure the fixes introduced in commits `5c0ca35` and `871936f` are applied.
* Deploy the Sigma rules provided in this brief to your SIEM to detect attempts at exploiting this vulnerability.
* Ensure that web server logs (or application-level logs for Joro's API) are configured to capture requests to `127.0.0.1:9090`, including `cs-method` and `cs-uri-stem` fields, to enable detection.
