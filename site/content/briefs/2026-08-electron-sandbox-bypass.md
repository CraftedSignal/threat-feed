---
title: Electron Sandboxed Iframe Popup Restriction Bypass
slug: 2026-08-electron-sandbox-bypass
description: A vulnerability in Electron, identified as CVE-2026-70608, allows sandboxed iframes to bypass 'allow-popups' restrictions and open new windows via the OpenURL navigation path.
date: "2026-08-05T21:26:10Z"
lastmod: "2026-08-05T21:26:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - electron
  - remote-code-execution
  - javascript
vendors:
  - OpenJS Foundation
products:
  - Electron (39.8.x)
  - Electron (40.x)
  - Electron (41.x)
  - Electron (42.x)
  - Electron (39.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204.001
    technique_name: User Execution
    evidence: The sandboxed iframe without the allow-popups keyword could still open a new window with no user interaction.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Untrusted web content could obtain access to the isolated preload world and, through it, every capability the preload script has.
    confidence_band: high
cves:
  - id: CVE-2026-70608
    cvss: 7.2
references:
  - https://github.com/advisories/GHSA-9f4c-93c8-jc8g
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-70608
  - https://github.com/advisories/GHSA-h7rp-cf8h-j98x
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-70601
action_plan:
  priority: elevated
  owners:
    - Development
    - AppSec
  immediate_actions:
    - action: 'Upgrade Electron packages to patched versions: 39.8.10, 41.10.3, or 42.0.1'
      owner: Development
      due: 72h
      evidence: Fixed versions list in GHSA-9f4c-93c8-jc8g
  mitigation_plan:
    - priority: immediate
      action: Update setWindowOpenHandler to explicitly deny window creation for untrusted content
      owner: Development
      addresses: CVE-2026-70608
      evidence: Workaround documentation in GHSA-9f4c-93c8-jc8g
updates:
  - at: "2026-08-05T21:26:26Z"
    level: L2
    summary: added coverage for Electron (39.x) +3 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-h7rp-cf8h-j98x
---

Electron versions prior to 39.8.10, 41.10.3, and 42.0.1 contain a security flaw, CVE-2026-70608, involving the iframe sandboxing implementation. When an application embeds untrusted content within a sandboxed iframe that lacks the 'allow-popups' keyword, the application expects to prevent new window creation from that iframe. However, the OpenURL navigation path fails to correctly enforce this restriction. Consequently, untrusted content can trigger the creation of new windows or bypass handlers defined in 'setWindowOpenHandler' without user interaction. This vulnerability represents a significant risk for desktop applications that render web content from third-party sources.

## Impact

Successful exploitation allows untrusted or malicious content rendered within an iframe to escape expected window-creation restrictions. This can lead to unwanted UI popups, potential phishing opportunities, or unauthorized navigation, depending on how the host application manages window open requests. Applications that rely solely on the iframe sandbox for security, rather than robust programmatic validation in 'setWindowOpenHandler', are susceptible to this sandbox breakout.

## Recommendation

Prioritized actions for development and security engineering teams:
- Upgrade Electron to versions 39.8.10, 41.10.3, or 42.0.1 or higher to patch CVE-2026-70608.
- Implement a secondary defense-in-depth measure by explicitly returning '{ action: 'deny' }' from the 'setWindowOpenHandler' for all untrusted or third-party web content as a programmatic safeguard against unexpected window navigation.
