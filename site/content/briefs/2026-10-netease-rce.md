---
title: Remote Code Execution in NetEase Cloud Music for Windows
slug: 2026-10-netease-rce
description: NetEase Cloud Music versions 3.1.38 and 3.1.39.205426 are vulnerable to remote code execution due to improper validation of URL schemes in the IPC bridge, allowing arbitrary local binary execution via API response forgery.
date: "2026-10-12T20:32:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:netease:cloud_music:3.1.38:*:*:*:*:windows:*:*
  - cpe:2.3:a:netease:cloud_music:3.1.39.205426:*:*:*:*:windows:*:*
tags:
  - remote-code-execution
  - cve-2026-109422
  - windows
  - ipc
vendors:
  - NetEase
products:
  - Cloud Music (3.1.38, 3.1.39.205426)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: An attacker can invoke os.navigateExternal with a file:// URL through an img onerror payload to execute arbitrary local binaries.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The renderer-process IPC bridge os.navigateExternal passes caller-supplied URLs to ShellExecuteW.
    confidence_band: high
cves:
  - id: CVE-2026-109422
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109422
rules:
  - title: Detect Suspicious Child Processes of NetEase Cloud Music
    description: Detects CVE-2026-109422 exploitation by monitoring for suspicious child processes launched by cloudmusic.exe
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Windows endpoints running NetEase Cloud Music
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability in specific versions
    - action: Deploy process-creation detection rule for cloudmusic.exe subprocesses
      owner: Detection Engineering
      due: 48h
      evidence: Supports identifying unauthorized binary execution
  hunt_leads:
    - lead: Search for unexpected child processes originating from cloudmusic.exe
      technique_id: T1204.002
      data_needed:
        - Endpoint process telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Renderer process IPC vulnerability allows arbitrary binary execution
---

The NetEase Cloud Music client for Windows (cloudmusic.exe), specifically versions 3.1.38 and 3.1.39.205426, contains a critical remote code execution vulnerability (CVE-2026-109422). The vulnerability resides in the renderer-process IPC bridge function `os.navigateExternal`, which incorrectly handles caller-supplied URLs. By failing to validate the URL scheme before passing it to the Windows API function `ShellExecuteW`, the application allows the execution of arbitrary local files.

The attack vector involves compromising the network traffic between the client and the update server. Because the application utilizes an unvalidated TLS connection and a publicly known AES key for API communications, an attacker can intercept and forge responses for the `/pc/upgrade/get` endpoint. By injecting an HTML payload containing a malicious `img` tag with an `onerror` handler that invokes `os.navigateExternal` with a `file://` URI, the attacker can force the application to execute local binaries under the privileges of the logged-in user.

## Impact

Successful exploitation results in full remote code execution in the context of the user running the NetEase Cloud Music client. This could lead to complete system compromise, data theft, or the installation of persistent backdoors on the affected machine. The vulnerability poses a significant risk to the large user base of the NetEase Cloud Music application on Windows platforms.

## Recommendation

Prioritize the identification of NetEase Cloud Music installations within the organization. While no patch is referenced in the source, users should restrict application network access and monitor for suspicious child processes spawned by `cloudmusic.exe`.

* Audit endpoints for the presence of NetEase Cloud Music versions 3.1.38 and 3.1.39.205426.
* Monitor for instances of `cloudmusic.exe` spawning unexpected child processes, specifically command shells or non-standard binaries, using EDR or Sysmon telemetry.
* Restrict the ability for `cloudmusic.exe` to initiate network connections to untrusted update servers via endpoint firewall policies.
