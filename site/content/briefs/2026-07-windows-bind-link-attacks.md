---
title: Windows Bind Link Attacks Can Hide Malware From EDR Tools
slug: 2026-07-windows-bind-link-attacks
description: Bitdefender researchers revealed how attackers can exploit Windows bind links, a legitimate operating system feature, to create conflicting filesystem views that conceal malware from endpoint detection and response (EDR) tools and other security mechanisms, enabling post-compromise evasion despite requiring administrative privileges.
date: "2026-07-15T13:02:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - edr-evasion
  - filesystem
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Attackers can exploit Windows’ bind links to create conflicting filesystem views to hide malware from endpoint detection and response (EDR) tools and other security mechanisms such as AMSI, AppLocker, Windows Firewall, and Sysmon.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: 'If the backing path is pointed at a DLL, it becomes file-binding: a process loads an attacker’s file from a path it trusts.'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: The file containing the attacker’s instructions becomes invisible to the EDR and the user.
    confidence_band: med
references:
  - https://www.securityweek.com/windows-bind-link-attacks-can-hide-malware-from-edr-tools/
---

Bitdefender researchers have demonstrated a sophisticated evasion technique leveraging Windows bind links to hide malware from endpoint detection and response (EDR) tools and other built-in security features. This technique, while requiring administrative privileges, is a significant post-compromise threat, as adversaries commonly achieve such access. Bind links, a legitimate kernel-level redirection mechanism (`bindflt.sys`), are manipulated to create a virtual path that points to a malicious file while appearing to be an innocuous one to security products. Three methods - file-binding, process-binding, and silo-binding - were detailed, allowing attackers to neutralize defenses like AMSI, AppLocker, Windows Firewall, and Sysmon. This evasion allows malicious payloads to execute undetected, presenting a serious challenge for current EDR architectures that rely heavily on file path trust.

## Attack Chain

1. An attacker gains initial access to a target system through an unspecified mechanism (e.g., exploit, phishing).
2. The attacker successfully escalates privileges to achieve administrator access on the compromised machine.
3. Using administrative rights, the attacker creates a bind link to redirect a legitimate Windows system DLL path (e.g., `C:\Windows\System32\amsi.dll`) to an attacker-controlled malicious DLL (file-binding).
4. A legitimate process (e.g., PowerShell) attempts to load the expected system DLL; the bind link transparently causes the malicious DLL to be loaded instead, neutralizing security features like AMSI without EDR detection based on the reported file path.
5. To further enhance stealth, the attacker establishes a user-defined Windows silo, creating an isolated execution environment.
6. Within this newly created silo, the attacker configures a bind link that maps a trusted executable path (e.g., `C:\Windows\System32\winver.exe`) to their actual malware payload.
7. Concurrently, from *outside* the silo, another bind link is established from the malware payload's true location, redirecting it to a clean, innocuous file (e.g., the real `winver.exe`).
8. The attacker executes the malware from within the silo; it runs undetected by external EDRs or scanners, which are misled by the external bind link into querying a clean file when inspecting the payload's path.

## Impact

The successful exploitation of Windows bind links allows attackers to effectively blind endpoint detection and response (EDR) tools, rendering them incapable of detecting malicious activity post-compromise. This technique can subvert critical Windows security features, including the Antimalware Scan Interface (AMSI), AppLocker, Windows Firewall, and Sysmon, preventing them from logging or blocking malicious actions. By executing malware in a hidden manner, attackers can maintain persistence, exfiltrate data, or deploy ransomware without triggering alarms. This significantly escalates the risk of successful advanced persistent threats and ransomware campaigns, as it undermines the security tools organizations rely on for detection and response.

## Recommendation

* **Implement advanced logging for kernel-level file system events**: Enable comprehensive logging for `bindflt.sys` operations and related file system API calls, if available through extended EDR or kernel-level monitoring solutions.
* **Monitor for privilege escalation**: Strengthen detection for initial privilege escalation attempts, as administrator access is a prerequisite for these bind link attacks.
* **Analyze process memory and behavior**: Deploy EDR solutions capable of analyzing process memory and behavior, rather than solely relying on file paths, to identify anomalous activity that might indicate bind link manipulation.
* **Scan for unexpected DLL loads**: Monitor for unusual DLL loads into trusted processes, regardless of the reported file path, to potentially identify instances where bind links have redirected legitimate paths to malicious files.
* **Review system configuration changes**: Regularly audit system configuration changes, particularly those related to file system drivers, symbolic links, and isolated processes (silos), which could indicate preparation for bind link attacks.
