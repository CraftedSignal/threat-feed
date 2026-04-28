---
title: OpenClaw Webchat Media Embedding Local-Root Containment Bypass
slug: 2026-04-openclaw-local-root-bypass
description: A vulnerability in OpenClaw versions 2026.4.7 to before 2026.4.15 allows a crafted tool-result media reference to cause the host to attempt local file reads or Windows UNC/network path access, potentially disclosing files or network credentials.
date: "2026-04-18T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - openclaw
  - local-file-inclusion
  - unc-path
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-mr34-9552-qr95
rules:
  - title: Detect Suspicious OpenClaw UNC Path Access
    description: Detects attempts by OpenClaw to access UNC paths, potentially indicating an exploitation of the local-root bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious OpenClaw File URL Access
    description: Detects attempts by OpenClaw to access file URLs, potentially indicating an exploitation of the local-root bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw versions 2026.4.7 through 2026.4.14 are vulnerable to a local-root containment bypass in the webchat media embedding feature. This flaw allows a malicious actor to craft a tool-result media reference with a local file path or UNC path that bypasses the intended `localRoots` containment policy. The vulnerability resides in the handling of media paths during webchat media block preparation on the host side. Successful exploitation could lead to the disclosure of allowed host files or the exposure of network credentials on Windows systems. The issue was reported by @Kherrisan and patched in OpenClaw version 2026.4.15.

## Attack Chain

1. An attacker crafts a malicious tool-result that contains a media reference with a file path intended to bypass local-root containment (e.g., a path outside the allowed `localRoots`).
2. The user interacts with the malicious tool-result within the OpenClaw webchat interface.
3. The webchat media embedding functionality attempts to normalize the media reference.
4. Due to the vulnerability, the crafted file path bypasses the `localRoots` containment check.
5. The host system attempts to read the file from the specified path (either local or UNC).
6. If successful, the file content is potentially exposed. On Windows, the system might attempt to access a UNC path, potentially exposing network credentials.
7. The webchat media block is prepared with the (potentially exposed) file content.
8. Although the vulnerability is triggered host-side before the user sees the final rendered result, sensitive information could be leaked.

## Impact

Successful exploitation of this vulnerability could lead to the disclosure of sensitive files on the host system. On Windows systems, exploitation may result in the exposure of network credentials if a UNC path is accessed. While the severity is medium because exploitation depends on a tool-result media path reaching the webchat embedding path, the sink is a host-side file read before the user sees the rendered result. This impacts OpenClaw installations running versions 2026.4.7 through 2026.4.14.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.15 or later to patch the vulnerability. The fix hardens the webchat media path and shared media resolver, rejecting remote-host `file://` URLs and Windows network paths.
*   Deploy the Sigma rule `Detect Suspicious OpenClaw UNC Path Access` to identify attempts to access UNC paths via OpenClaw.
*   Review the code changes in commits `1470de5d3e0970856d86cd99336bb8ada3fe87da`, `6e58f1f9f54bca1fea1268ec0ee4c01a2af03dde`, and `52ef42302ead9e183e6c8810e0a04ee4ef8ae9fc` to understand the implemented security measures in version 2026.4.15.
