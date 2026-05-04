---
title: Detection of Downloaded URL Files Used in Phishing Campaigns
slug: 2024-01-downloaded-url-files
description: This detection rule identifies downloaded .url shortcut files on Windows systems, often used in phishing campaigns, by monitoring their creation events and flagging those from non-local sources, enabling early threat detection.
date: "2024-01-04T17:49:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - phishing
  - execution
  - url-file
  - windows
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_downloaded_url_file.toml
rules:
  - title: Downloaded URL Files Created
    description: Detects the creation of .url shortcut files downloaded from outside the local network, commonly used in phishing campaigns.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1566
    data_sources:
      - file_event
      - windows
  - title: Suspicious Process Creating Downloaded URL Files
    description: Detects suspicious processes, other than explorer.exe, creating downloaded .url shortcut files, which can indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers commonly use .url shortcut files in phishing campaigns to deliver malicious payloads. These files, when downloaded from non-local sources, may bypass traditional security measures. This detection rule identifies such files by monitoring their creation events on Windows systems. The rule focuses on files with the .url extension and a zone identifier indicating they originated from outside the local network. These files are often delivered via email or malicious websites, tricking users into clicking them, which can lead to the execution of arbitrary commands or the redirection to malicious websites. This technique allows attackers to gain initial access or execute malicious code on the victim's machine.

## Attack Chain

1.  The attacker crafts a phishing email or a malicious website containing a link to a .url file.
2.  The victim clicks the link, resulting in the download of the .url file to their Windows system.
3.  The .url file is created on the filesystem, triggering a file creation event.
4.  The operating system assigns a Zone Identifier to the file, marking it as originating from an external source.
5.  The victim double-clicks the .url file, which contains a URL pointing to a malicious website or an executable.
6.  The operating system attempts to open the URL using the default web browser or execute the embedded command.
7.  If the URL points to a malicious website, the victim may be prompted to download and execute malware.
8.  The malware executes, potentially leading to system compromise, data theft, or other malicious activities.

## Impact

Successful exploitation can lead to the execution of arbitrary commands, redirection to malicious websites, and subsequent malware infection. If successful, attackers can compromise user systems, steal sensitive information, or establish a foothold for further malicious activities within the organization's network. The impact can range from individual system compromise to broader network breaches, depending on the attacker's objectives and the extent of the infection.

## Recommendation

*   Deploy the Sigma rule `Downloaded URL Files Created` to your SIEM to detect the creation of downloaded .url files with a non-local Zone Identifier and tune for your environment.
*   Investigate any `file creation` events where `file.extension == "url"` and `file.Ext.windows.zone_identifier == 3` using the provided investigation steps in the advisory.
*   Update security policies and endpoint protection configurations to block the download and execution of .url files from untrusted sources, as mentioned in the advisory.
*   Educate users on safe downloading practices and the risks associated with opening .url files from untrusted sources, as highlighted in the advisory's false positive analysis.
