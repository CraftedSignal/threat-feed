---
title: Potential Defense Evasion Via Rename Of Highly Relevant Binaries
slug: 2026-07-renamed-binaries-evasion
description: This brief details a defense evasion technique where attackers rename legitimate Windows system binaries to mask malicious activity, bypassing security solutions that rely on process names for detection.
date: "2026-07-03T14:22:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - process-creation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.
    confidence_band: high
references:
  - https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html
  - https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html
  - https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/megacortex-ransomware-spotted-attacking-enterprise-networks
  - https://twitter.com/christophetd/status/1164506034720952320
  - https://threatresearch.ext.hp.com/svcready-a-new-loader-reveals-itself/
  - https://www.huntress.com/blog/malicious-browser-extention-crashfix-kongtuke
rules:
  - title: Potential Defense Evasion Via Rename Of Highly Relevant Binaries
    description: Detects the execution of a renamed binary often used by attackers or malware leveraging the Sysmon OriginalFileName datapoint to identify original process identity.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1036.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This brief details a common defense evasion technique employed by various threat actors and malware, which involves renaming legitimate Windows system binaries (such as `powershell.exe`, `certutil.exe`, or `rundll32.exe`) to mask their malicious activity. By altering the filename, attackers attempt to bypass security solutions that rely on process names for detection, whitelisting, or behavioral analysis. This technique is crucial for defenders to address as it allows the abuse of trusted processes for malicious ends, enabling subsequent actions like persistence or execution without immediate detection. Detection leverages the `OriginalFileName` field in Sysmon events, which retains the original name of the executable regardless of its current filename, providing a robust way to identify this stealthy behavior. This method has been observed in various campaigns, including ransomware like MegaCortex.

## Attack Chain

1.  **Initial Access**: An attacker gains initial access to a target system through various means (e.g., phishing, exploiting a vulnerability).
2.  **Staging Malicious Binary**: The attacker transfers or creates a malicious payload or script on the compromised system.
3.  **Identify Legitimate Binary**: The attacker identifies a legitimate, trusted Windows system binary, such as `powershell.exe`, `certutil.exe`, or `rundll32.exe`, commonly used for system administration.
4.  **Rename Binary for Evasion**: The attacker copies the legitimate binary and renames the copy to a less suspicious name (e.g., `powershell.exe` renamed to `update.exe` or `svchost.exe`).
5.  **Execute Renamed Binary**: The attacker executes the renamed binary (e.g., `update.exe`) to carry out malicious operations, such as executing a script, downloading additional payloads, or performing lateral movement.
6.  **Defense Evasion**: The renamed process runs with the functionality of the original system binary but appears as a different, potentially benign, process name to security tools that do not inspect the `OriginalFileName` metadata.
7.  **Achieve Objective**: This evasion enables the attacker to achieve their objectives, such as establishing persistence, escalating privileges, exfiltrating data, or deploying ransomware, with a reduced risk of detection.

## Impact

If this defense evasion technique is successful, attackers can execute powerful system tools under disguise, significantly increasing the likelihood of successful persistence, lateral movement, or data exfiltration without triggering process-name-based security alerts. This can extend an attacker's dwell time and the scope of compromise, as seen in ransomware attacks like MegaCortex which utilized this method to distribute payloads. The ability to masquerade malicious activity under the guise of legitimate processes directly undermines the effectiveness of security monitoring and incident response efforts.

## Recommendation

*   Deploy the provided Sigma rule (`Potential Defense Evasion Via Rename Of Highly Relevant Binaries`) to your SIEM.
*   Ensure Sysmon is configured to log process creation events (`EventID 1`) including the `OriginalFileName` field, which is critical for the detection rule.
*   Tune the rule for your environment by analyzing `falsepositives` described in the rule, such as custom applications that rename binaries, and add specific exclusions if necessary.
*   Prioritize investigation of alerts generated by the `Potential Defense Evasion Via Rename Of Highly Relevant Binaries` rule, as they indicate a strong likelihood of malicious activity.
