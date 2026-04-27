---
title: SiYuan Zero-Click NTLM Theft and Blind SSRF via Mermaid Diagrams
slug: 2026-04-siyuan-ntlm-ssrf
description: SiYuan is vulnerable to zero-click NTLM hash theft on Windows and blind SSRF on all platforms due to insecure Mermaid.js configuration, where a malicious Mermaid diagram containing a protocol-relative URL can be injected into a note, causing the Electron client to fetch the URL, triggering SMB authentication on Windows and sending the victim's NTLMv2 hash to the attacker. On macOS and Linux, the request acts as a tracking pixel and blind SSRF.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - siyuan
  - ntlm
  - ssrf
  - credential-theft
  - mermaid
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40107
    epss: 0.0005
references:
  - https://github.com/advisories/GHSA-w95v-4h65-j455
rules:
  - title: Detect SiYuan Mermaid NTLM Theft Attempt
    description: Detects SMB connections originating from SiYuan processes, potentially indicating NTLM theft via a malicious Mermaid diagram.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect SiYuan Mermaid SSRF Attempt
    description: Detects HTTP requests from SiYuan processes with suspicious URLs, potentially indicating SSRF via a malicious Mermaid diagram.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

SiYuan, a note-taking application, is vulnerable to a zero-click NTLM hash theft and blind SSRF exploit due to insecure configuration of Mermaid.js. The application configures Mermaid.js with `securityLevel: "loose"` and `htmlLabels: true`, which allows `<img>` tags with `src` attributes to bypass sanitization and be injected into SVG `<foreignObject>` blocks. When a user opens a note containing a malicious Mermaid diagram with a protocol-relative URL (e.g., `//attacker.com/image.png`), the…
