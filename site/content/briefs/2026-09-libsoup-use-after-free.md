---
title: Heap Use-After-Free in libsoup HTTP/2 Implementation
slug: 2026-09-libsoup-use-after-free
description: A heap use-after-free vulnerability in the libsoup HTTP/2 client allows malicious servers or MITM attackers to trigger memory corruption via specifically timed GOAWAY frames during file uploads.
date: "2026-09-04T09:24:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gnome:libsoup:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
vendors:
  - GNOME
products:
  - libsoup
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This can lead to memory corruption, potentially resulting in information disclosure or arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-85197
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85197
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Track and monitor security advisories for libsoup to determine when patched packages are available for distribution.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-85197 status
  mitigation_plan:
    - priority: immediate
      action: Upgrade libsoup to the fixed version once identified by the distribution provider.
      owner: IT Operations
      addresses: CVE-2026-85197
      evidence: Vulnerability requires software patch for resolution
---

A heap use-after-free vulnerability (CVE-2026-85197) has been identified in the libsoup library, a core networking component frequently used by GNOME applications. The flaw resides in the HTTP/2 client implementation and is triggered when an application attempts an asynchronous file upload. If a malicious server or an attacker performing a Man-in-the-Middle (MITM) interception injects a GOAWAY frame during the file body read process, the library may access freed memory. This memory corruption poses a significant security risk, as it can be leveraged by an attacker to facilitate arbitrary code execution or unauthorized information disclosure within the context of the affected GNOME application. Given that many desktop applications rely on libsoup for network connectivity, this vulnerability could be exploited to compromise user data or system integrity.

## Impact

Successful exploitation of CVE-2026-85197 can lead to arbitrary code execution or memory-based information disclosure within the user session. This impacts users running GNOME-based applications that utilize libsoup for network operations. The CVSS score of 7.6 indicates a high-severity threat that could lead to full application compromise on affected Linux distributions.

## Recommendation

Prioritized actions for security teams include identifying systems running libsoup and applying patches as soon as they become available from Linux distribution maintainers. Monitor for unexpected application crashes related to network-heavy tasks, as these may indicate attempted exploitation or stability issues resulting from this memory corruption vulnerability.

- Update libsoup across all Linux workstations and servers once the package maintainer releases the corrected version addressing CVE-2026-85197.
- Implement network monitoring to detect unexpected or suspicious HTTP/2 traffic patterns originating from desktop applications, which may indicate an attempt to interact with malicious server infrastructure.
