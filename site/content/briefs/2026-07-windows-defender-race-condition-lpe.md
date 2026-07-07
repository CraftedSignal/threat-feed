---
title: Windows Defender Race Condition (EDB-52612) Leads to Local Privilege Escalation and AV Bypass
slug: 2026-07-windows-defender-race-condition-lpe
description: A critical local race condition (EDB-52612) exists in Microsoft Windows Defender's MsMpEng.exe, specifically between its cleanup routine (`MpCleanCallbackFunction`) and Volume Shadow Copy creation, allowing Local Privilege Escalation (LPE) to NT AUTHORITY\SYSTEM and temporary disabling of antivirus protection through a use-after-free vulnerability, with a public exploit demonstrating the risk.
date: "2026-07-06T13:22:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - local-privilege-escalation
  - race-condition
  - windows-defender
  - exploit-db
  - vulnerability
  - endpoint
vendors:
  - Microsoft Corporation
products:
  - Windows Defender Antivirus (MsMpEng.exe)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: LPE (Local Privilege Escalation) to NT AUTHORITY\SYSTEM via `CreateProcessAsUser`
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52612
  - https://gitlab.com/nu11secur1ty/0/-/raw/main/README.md?ref_type=heads
iocs:
  - type: url
    value: https://gitlab.com/nu11secur1ty/0.git
  - type: url
    value: https://gitlab.com/nu11secur1ty/0/-/raw/main/README.md?ref_type=heads
  - type: url
    value: https://www.patreon.com/nu11secur1ty/posts/honda-exploit-160798929
ioc_counts:
  url: 3
---

A critical local race condition vulnerability (EDB-52612) affecting Microsoft Windows Defender's scanning engine (MsMpEng.exe) has been publicly disclosed on Exploit-DB. Published by nu11secur1ty on July 6, 2026, this flaw exists between Defender's cleanup routine (`MpCleanCallbackFunction`) and Volume Shadow Copy creation. Successful exploitation, demonstrated by a public Proof-of-Concept, grants local privilege escalation (LPE) to `NT AUTHORITY\SYSTEM` via `CreateProcessAsUser` and can trigger a use-after-free condition, causing MsMpEng.exe to crash. This not only elevates attacker privileges but also leaves the compromised system temporarily without antivirus protection. The availability of a working exploit elevates the immediate risk for organizations running unpatched Windows systems, requiring immediate attention from defenders.

## Attack Chain

1.  An attacker gains initial local access to a vulnerable Windows system, typically through other means (e.g., social engineering, exploiting a user-level application vulnerability).
2.  The attacker executes a malicious process that leverages Windows API calls like `OpenVirtualDisk` and `AttachVirtualDisk` to mount a fake ISO image.
3.  The malicious process elevates its own or specific thread priorities to `REALTIME_PRIORITY_CLASS` and `THREAD_PRIORITY_TIME_CRITICAL` to enhance its ability to win race conditions.
4.  The attacker initiates operations designed to trigger a race condition between Windows Defender's `MpCleanCallbackFunction` (cleanup routine) and the system's Volume Shadow Copy creation.
5.  During the race, the attacker manipulates file system operations to substitute or plant malicious files in a location Defender is processing for cleanup.
6.  The vulnerability allows the malicious process to execute code or manipulate system services using `CreateProcessAsUser` with `NT AUTHORITY\SYSTEM` privileges.
7.  The system process `MsMpEng.exe` experiences a use-after-free condition and crashes, leaving the system temporarily without active antivirus protection.
8.  The attacker maintains `NT AUTHORITY\SYSTEM` privileges, enabling full control over the compromised system, persistence, and further malicious activities without AV detection.

## Impact

A successful exploitation of this race condition results in an attacker achieving `NT AUTHORITY\SYSTEM` privileges on the compromised Windows host. This complete control allows for arbitrary code execution, data exfiltration, deployment of further malware, and establishment of persistence. Additionally, the exploit can cause the `MsMpEng.exe` process to crash due to a use-after-free condition, temporarily disabling Windows Defender's real-time protection and leaving the system vulnerable to subsequent attacks without immediate antivirus safeguards.

## Recommendation

*   Apply the official Microsoft security update as soon as it becomes available to patch the race condition vulnerability (EDB-52612) in Windows Defender (MsMpEng.exe).
*   Implement advanced API monitoring on endpoints for suspicious calls to `OpenVirtualDisk` or `AttachVirtualDisk` from non-system processes, particularly when observed alongside rapid process priority changes, to potentially identify exploitation attempts.
*   Focus endpoint detection on `CreateProcessAsUser` calls where the resulting process runs as `NT AUTHORITY\SYSTEM` but is spawned by an unusual parent process or exhibits suspicious command-line arguments.
*   Configure monitoring for crashes of `MsMpEng.exe` (e.g., via event logs) that are not attributed to legitimate system reconfigurations or updates, as this could indicate a successful use-after-free exploitation.
