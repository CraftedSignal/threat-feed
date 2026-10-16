---
title: Information Disclosure and DoS in FreeRDP via Heap Memory Leak
slug: 2026-10-freerdp-heap-disclosure
description: FreeRDP versions before 3.0.0 and 3.6.0 before 3.32.0 are vulnerable to heap memory disclosure and denial-of-service attacks triggered by a malicious RDP server sending crafted progressive tile sequences.
date: "2026-10-12T18:34:17Z"
lastmod: "2026-10-16T04:23:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:freerdp:freerdp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rdp
  - remote-access
  - memory-corruption
  - injection
  - linux
  - heap-overflow
  - cve-2026-111380
  - remote-code-execution
  - freerdp
vendors:
  - FreeRDP
products:
  - FreeRDP (< 3.0.0)
  - FreeRDP (3.6.0 - 3.32.0)
  - FreeRDP (3.0.0-beta1 to 3.31.x)
  - FreeRDP (< 3.32.0)
  - FreeRDP (3.0.0 - 3.31.0)
  - FreeRDP (3.29.0 - 3.31.x)
affected_os:
  - macOS
  - iOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A malicious RDP server can send a crafted WBT_TILE_FIRST then WBT_TILE_UPGRADE sequence to paint heap bytes onscreen or abort the client process.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker can inject synthetic keystrokes into the host user's X11 session via XTEST.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A malicious RDP server can offer a grayscale JPEG via clipboard redirection, corrupting client memory and crashing it when the item is pasted as CF_DIB bitmap data.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: FreeRDP from 3.0.0 before 3.32.0 contains an uncontrolled resource consumption vulnerability in parse_nla_mode_pdu that allows unauthenticated attackers to exhaust server memory.
    confidence_band: high
cves:
  - id: CVE-2026-109242
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109242
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109676
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110837
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110838
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110839
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111378
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111380
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111381
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111382
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade all instances of FreeRDP to 3.32.0 or later
      owner: IT Operations
      due: 72h
      evidence: Source document identifies version 3.32.0 as the remediation target.
  mitigation_plan:
    - priority: immediate
      action: Avoid connecting to untrusted or unauthorized RDP servers
      owner: SOC
      addresses: CVE-2026-109242
      evidence: Exploitation requires a malicious server to send crafted sequences.
updates:
  - at: "2026-10-15T02:34:04Z"
    level: L2
    summary: added coverage for FreeRDP (< 3.32.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110839
  - at: "2026-10-16T04:23:21Z"
    level: L1
    summary: added coverage for FreeRDP (3.0.0 - 3.31.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111378
  - at: "2026-10-16T04:23:33Z"
    level: L2
    summary: added coverage for FreeRDP (3.29.0 - 3.31.x)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111380
  - at: "2026-10-16T04:23:38Z"
    level: L2
    summary: added coverage for FreeRDP (< 3.32.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111381
  - at: "2026-10-16T04:23:44Z"
    level: L2
    summary: added coverage for FreeRDP (< 3.32.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111382
---

FreeRDP versions prior to 3.0.0 and 3.6.0 before 3.32.0 contain a vulnerability where uninitialized heap memory from un-decoded progressive tiles is rendered. This occurs because the tile buffer is allocated without zeroing out memory, allowing an attacker to access sensitive information residing in the heap. A malicious RDP server can exploit this by sending a specifically crafted sequence of WBT_TILE_FIRST and WBT_TILE_UPGRADE messages. Depending on the server's input, the client may render leaked heap bytes directly to the screen or encounter an unhandled memory condition leading to a process crash (Denial of Service). This issue affects all platforms utilizing the affected FreeRDP versions as a remote desktop client.

## Impact

Successful exploitation allows a malicious server to view potentially sensitive data stored in the client's heap memory or force the client application to terminate. This poses a risk to users connecting to untrusted RDP servers, as memory contents could be visualized on the client's display.

## Recommendation

- Upgrade to FreeRDP version 3.32.0 or later to ensure heap buffers are properly initialized.
- Review patch notes for CVE-2026-109242 to verify build requirements.
- Until patching is possible, restrict RDP client connections to known, trusted servers and avoid connecting to unauthorized or public-facing RDP infrastructure.
