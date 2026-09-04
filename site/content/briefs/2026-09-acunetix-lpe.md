---
title: Local Privilege Escalation in Acunetix Web Vulnerability Scanning Engine
slug: 2026-09-acunetix-lpe
description: Acunetix 25.11.251107123 for Windows is vulnerable to local privilege escalation via DLL hijacking in the Web Vulnerability Scanning Engine (wvsc.exe) due to insecure directory path handling.
date: "2026-09-04T15:27:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:acunetix:acunetix:25.11.251107123:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - windows
  - local-exploitation
vendors:
  - Acunetix
products:
  - Acunetix (25.11.251107123)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: A low-privileged local attacker can create the missing directory and place a malicious file at the expected path, and cause the SYSTEM-level wvsc.exe process to load and execute it.
    confidence_band: high
cves:
  - id: CVE-2026-6958
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6958
rules:
  - title: Detect CVE-2026-6958 - Potential DLL Hijacking in Acunetix
    description: Detects the creation of specific folders in application paths by non-privileged users that are often associated with DLL hijacking and LPE.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Acunetix to a non-vulnerable version immediately.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-6958 requires patching.
  mitigation_plan:
    - priority: immediate
      action: Remove write permissions for non-privileged users to the Acunetix installation directory.
      owner: IT Operations
      addresses: CVE-2026-6958
      evidence: Preventing creation of the directory is a viable stop-gap.
---

Acunetix 25.11.251107123 for Windows contains a critical local privilege escalation (LPE) vulnerability in its Web Vulnerability Scanning Engine (wvsc.exe). The issue stems from the application expecting certain OpenSSL-related files to exist in a specific path that is not hardcoded or properly restricted. A low-privileged local user can proactively create the missing directory structure and inject a malicious DLL file into the expected location. When the wvsc.exe process, which executes with SYSTEM privileges, attempts to load these dependencies, it loads the attacker-controlled file instead. This results in arbitrary code execution with SYSTEM-level permissions. This vulnerability, identified as CVE-2026-6958, allows any local attacker to elevate their privileges to full administrative control over the host system.

## Impact

Successful exploitation of this vulnerability allows a low-privileged local user to escalate their permissions to the SYSTEM level on a system running the affected version of Acunetix. This can lead to total system compromise, including the installation of persistent backdoors, data exfiltration, and lateral movement within the network. The vulnerability impacts organizations using Acunetix 25.11.251107123 on Windows platforms.

## Recommendation

1. Patch immediately: Upgrade Acunetix installations to a version that addresses CVE-2026-6958.
2. Implement monitoring: Monitor for file creation events in directories where high-privilege applications search for library dependencies.
3. Restrict permissions: Ensure that standard user accounts do not have write access to system directories or application installation folders where such hijacking can occur.
