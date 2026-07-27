---
title: Rundll32 UNC Path Execution for Malicious DLL Loading
slug: 2026-07-rundll32-unc-path-execution
description: Threat actors are observed abusing the legitimate Windows utility rundll32.exe to execute malicious DLLs from remote UNC network paths, facilitating execution and lateral movement within compromised environments.
date: "2026-07-27T16:18:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - code-execution
  - stealth
  - malware
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: Detects rundll32 execution where the DLL is located on a remote location (share). Threat actors can abuse the rundll32.exe binary to execute remote DLLs from a UNC path.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Detects rundll32 execution where the DLL is located on a remote location (share). Threat actors can abuse the rundll32.exe binary to execute remote DLLs from a UNC path.
    confidence_band: high
references:
  - https://www.cybereason.com/blog/rundll32-the-infamous-proxy-for-executing-malicious-code
  - https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_rundll32_unc_path.yml
rules:
  - title: Rundll32 UNC Path Execution
    description: Detects rundll32.exe attempting to load a DLL from a remote UNC network share, a technique often abused by threat actors for execution and lateral movement.
    platform: sigma
    severity: high
    tactics:
      - execution
      - lateral_movement
      - stealth
    techniques:
      - T1021.002
      - T1218.011
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Threat actors are actively leveraging `rundll32.exe`, a legitimate Windows utility, to execute malicious Dynamic Link Libraries (DLLs) stored on remote Universal Naming Convention (UNC) network paths. This technique allows attackers to bypass certain security controls, execute arbitrary code, and move laterally across a network. The execution of DLLs from UNC shares enables adversaries to stage payloads on accessible network resources, rather than directly on the victim's local disk, potentially reducing their footprint and complicating detection. This method has been observed as part of intrusion chains, including those involving the ACR Stealer, highlighting its use in real-world campaigns for stealthy code execution and further compromise.

## Attack Chain

1. **Initial Foothold**: An attacker gains initial access to a network or system through an unspecified vector (e.g., exploiting a vulnerability, phishing).
2. **Lateral Movement Preparation**: The adversary identifies or establishes an accessible network share (SMB/CIFS) on a compromised host or attacker-controlled infrastructure within the target environment.
3. **Malicious DLL Staging**: A malicious DLL, often disguised as a legitimate file, is placed onto the prepared remote UNC share.
4. **Remote Execution Command**: The attacker remotely executes `rundll32.exe` on a target workstation or server, providing the UNC path to the staged malicious DLL and an exported function to execute. This command could be initiated via remote services, WMI, or other execution methods.
5. **DLL Loading and Execution**: The `rundll32.exe` process attempts to load the DLL from the specified UNC path, bypassing local file execution policies for signed binaries.
6. **Malicious Payload Delivery**: Upon successful loading, the malicious DLL executes its payload, which can range from reconnaissance and credential dumping to establishing persistence, deploying additional malware (e.g., stealer, ransomware), or exfiltrating data.

## Impact

Successful exploitation of this technique allows threat actors to achieve arbitrary code execution on target systems, leading to potential complete system compromise. The use of a legitimate signed binary like `rundll32.exe` makes detection challenging, contributing to increased dwell time and enabling deeper penetration into an organization's network. Observed in campaigns like those involving the ACR Stealer, this method facilitates data theft, further lateral movement, and can serve as a stepping stone for ransomware deployment or other high-impact activities, ultimately leading to significant financial and reputational damage.

## Recommendation

* Deploy the Sigma rule "Rundll32 UNC Path Execution" to your SIEM to detect instances of rundll32.exe attempting to load DLLs from network shares.
* Ensure Sysmon process-creation logging is enabled on all Windows endpoints to provide the necessary telemetry for the `process_creation` log source.
* Implement strict network segmentation and access controls to limit SMB/CIFS share accessibility and prevent unauthorized staging of malicious files.
* Review and monitor outbound network connections from `rundll32.exe` processes for suspicious activity, as identified in the `https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/` reference.
