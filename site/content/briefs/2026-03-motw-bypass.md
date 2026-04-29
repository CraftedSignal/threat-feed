---
title: MOTW Bypass via CAB, TAR, and 7-Zip Chaining
slug: 2026-03-motw-bypass
description: A newly discovered Mark of the Web (MOTW) bypass technique utilizes a chain of CAB, TAR, and 7-Zip archives to circumvent SmartScreen and execute files without security warnings.
date: "2026-03-19T17:31:15Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - motw
  - bypass
  - phishing
  - defense-evasion
  - archive
  - 7-zip
  - cab
  - tar
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1553
    technique_name: Subvert Trust Relationship
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationship
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ry6uu9/is_motw_bypass_possible_in_2026/
  - https://youtu.be/pQxiPwGTBL8
iocs:
  - type: url
    value: https://youtu.be/pQxiPwGTBL8
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious Archive Chaining
    description: Detects suspicious process chains involving makecab.exe, 7z.exe, and tar.exe which may indicate exploitation of archive chaining vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Archive Extraction from Downloaded CAB
    description: Detects archive extraction from CAB files that originated from a download location, indicating a potential MOTW bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A new MOTW bypass technique has emerged that chains a CAB file with two TAR archives nested within a 7-Zip archive. This method effectively strips the Zone.Identifier stream from downloaded files, preventing the display of SmartScreen prompts or security warnings. Many organizations rely on MOTW and SmartScreen as a crucial layer of defense against phishing attacks. This bypass, affecting fully patched environments, allows attackers to execute arbitrary code without the usual security checks, potentially leading to malware infection or data compromise. The technique is not a rehash of older 7-Zip MOTW issues but a novel approach to evade detection based on Zone.Identifier.

## Attack Chain

1.  Attacker crafts a malicious payload.
2.  Attacker packages the payload into a TAR archive.
3.  The TAR archive is nested inside another TAR archive.
4.  The nested TAR archives are then compressed into a 7-Zip archive using 7z.exe.
5.  The 7-Zip archive is packaged into a CAB archive using makecab.exe.
6.  The CAB archive is distributed to the victim, potentially via phishing or drive-by download.
7.  The victim opens the CAB archive, extracting the nested 7-Zip, TAR, and payload.
8.  The payload executes without a Zone.Identifier stream, bypassing MOTW and SmartScreen, potentially leading to malware infection or unauthorized access.

## Impact

Successful exploitation allows attackers to bypass security controls that rely on MOTW and SmartScreen. This can lead to malware infections, data breaches, or other malicious activities. The bypass affects fully patched environments, increasing the scope of potential victims. The absence of security warnings makes it more likely that users will execute the malicious payload, increasing the success rate of attacks.

## Recommendation

*   Implement detections for unusual process chains involving `makecab.exe`, `7z.exe`, and `tar.exe` as these tools are used in the bypass (see Sigma rule "Detect Suspicious Archive Chaining").
*   Monitor for archive extractions from unusual locations, especially those originating from downloaded CAB files, using file event logging and process monitoring (see Sigma rule "Detect Archive Extraction from Downloaded CAB").
*   Analyze network connections from processes spawned from archive extractions, as they may indicate command and control or data exfiltration.
*   Block the URL `https://youtu.be/pQxiPwGTBL8` to prevent users from accessing potentially malicious content related to this bypass.
