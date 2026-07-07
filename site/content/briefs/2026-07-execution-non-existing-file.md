---
title: Execution Of Non-Existing File via Process Ghosting
slug: 2026-07-execution-non-existing-file
description: This brief details the Process Ghosting technique, an advanced evasion method leveraged by attackers to create and execute processes from files that no longer exist on disk, challenging traditional endpoint detection solutions and hindering forensic investigations.
date: "2026-07-06T15:49:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - evasion
  - process-injection
  - windows
  - stealth
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    evidence: Detects process creation events where the Image field lacks an absolute path, which occurs when the backing file no longer exists on disk at the time of logging - commonly caused by Process Ghosting or other unorthodox process creation techniques.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: occurs when the backing file no longer exists on disk at the time of logging - commonly caused by Process Ghosting or other unorthodox process creation techniques.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_image_missing.yml
  - https://pentestlaboratories.com/2021/12/08/process-ghosting/
  - https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack
rules:
  - title: Execution Of Non-Existing File
    description: Detects process creation events where the Image field lacks an absolute path, which occurs when the backing file no longer exists on disk at the time of logging — commonly caused by Process Ghosting or other unorthodox process creation techniques, often for evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - evasion
      - privilege_escalation
    techniques:
      - T1055
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This brief details the Process Ghosting technique, an advanced evasion method leveraged by attackers to create and execute processes from files that no longer exist on disk. First documented in late 2021 by security researchers, Process Ghosting capitalizes on specific Windows kernel mechanics and Native API calls to bypass traditional endpoint detection and response (EDR) solutions that rely on disk-based file integrity checks for process attribution. Attackers employ this method to obfuscate their activities, making it challenging for defenders to trace the origin of a malicious process, attribute it to a specific executable, and ultimately hinder forensic investigations. This technique is a significant concern for security teams as it allows malicious code to run with reduced detectability and can be combined with other techniques like process injection (T1055) or privilege escalation (TA0004).

## Attack Chain

1.  Attacker initiates a process creation using Windows Native APIs, specifically `NtCreateProcessEx` and `NtCreateSection`, preparing to map a file into memory.
2.  A transactional file is created on disk (e.g., using `CreateFileTransacted`), containing the malicious payload, and then mapped into a new section object.
3.  The transaction for the file is then rolled back (`RollbackTransaction`), causing the original malicious file to be immediately removed from disk.
4.  Despite the file's deletion from disk, its content remains mapped in the process's memory section, appearing as a ghost image.
5.  The attacker can optionally use `NtWriteVirtualMemory` to further modify or inject code into the mapped memory region, potentially escalating privileges or modifying behavior.
6.  The process execution is then started (e.g., via `NtCreateThreadEx`), running the malicious code directly from memory.
7.  Logging systems, attempting to record the process's original image path (like Sysmon Event ID 1), find no corresponding file on disk, leading to a null or non-absolute path in process creation logs, effectively evading disk-based file integrity checks.

## Impact

Successful deployment of Process Ghosting significantly degrades an organization's ability to detect and respond to malicious activity. By executing from non-existent files, attackers can bypass security controls that scan or monitor executable files on disk, such as antivirus and some EDR capabilities. This technique complicates incident response, making forensic analysis more difficult as the original malicious binary is not available for collection and attribution. If undetected, this can lead to prolonged attacker presence, data exfiltration, system compromise, or further deployment of ransomware, increasing recovery costs and potential regulatory fines, potentially affecting any sector.

## Recommendation

*   Enable Sysmon process-creation logging (Event ID 1) with `Image` and `CommandLine` fields to capture the necessary telemetry for the rule "Execution Of Non-Existing File".
*   Deploy the "Execution Of Non-Existing File" Sigma rule in this brief to your SIEM and tune it for your environment to detect `Image` paths that are `null` or non-absolute.
*   Review logs for processes with null or non-absolute paths in the `Image` field, specifically looking for `MemCompression`, `Registry`, `System`, `vmmem`, or `vmmemWSL` processes with non-absolute paths which may indicate this evasion technique.
