---
title: Detection of Malicious Browser Extension Installation
slug: 2024-01-browser-extension-install
description: This rule identifies the installation of potentially malicious browser extensions, which adversaries can leverage for persistence and unauthorized activity by monitoring file creation events in common browser extension directories on Windows systems.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - browser-extension
  - windows
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_browser_extension_install.toml
  - https://attack.mitre.org/techniques/T1176/
  - https://attack.mitre.org/techniques/T1176/001/
  - https://attack.mitre.org/tactics/TA0003/
rules:
  - title: Browser Extension Install via File Creation
    description: Detects the creation of browser extension files (.xpi or .crx) in common browser extension directories, excluding known safe processes and extensions.
    platform: sigma
    severity: low
    tactics:
      - persistence
    data_sources:
      - file_event
      - windows
  - title: Suspicious Process Installing Browser Extension
    description: Detects a non-browser process creating browser extension files in the browser profile directory.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies the installation of browser extensions on Windows systems, which can be a sign of malicious activity. Threat actors may install malicious browser extensions through app store downloads disguised as legitimate extensions, social engineering tactics, or by directly compromising a system. These extensions can then be used for persistence, data theft, or other malicious purposes. The rule focuses on monitoring file creation events related to browser extension installations, specifically targeting the file paths and types associated with Firefox (.xpi) and Chromium-based browsers (.crx). It excludes known safe processes and extensions to reduce false positives. This detection is relevant for defenders because malicious browser extensions can provide a persistent foothold for attackers, allowing them to maintain access to compromised systems and user data. The rule is based on EQL and can be used with Elastic Defend, Microsoft Defender XDR, SentinelOne Cloud Funnel, and Sysmon data.

## Attack Chain

1.  The user's system is compromised, potentially through social engineering or existing malware.
2.  The attacker gains access to the system and attempts to install a malicious browser extension.
3.  The attacker drops the extension file (.xpi for Firefox, .crx for Chromium) into the appropriate browser extension directory (e.g., `C:\\Users\\*\\AppData\\Roaming\\*\\Profiles\\*\\Extensions\\` for Firefox or `C:\\Users\\*\\AppData\\Local\\*\\*\\User Data\\Webstore Downloads\\` for Chromium).
4.  A file creation event is triggered as the extension file is created in the target directory.
5.  The detection rule identifies this file creation event based on the file name and path, filtering out known safe processes like firefox.exe.
6.  The malicious extension installs itself into the browser.
7.  The extension gains persistence by loading every time the browser starts.
8.  The attacker can now perform malicious actions such as monitoring browsing activity, stealing credentials, or injecting malicious content into web pages.

## Impact

A successful attack using malicious browser extensions can lead to persistent access to the compromised system, allowing attackers to steal sensitive information such as credentials, financial data, or personal information. This can result in financial loss, identity theft, and reputational damage. The installation of malicious extensions can also lead to the injection of malicious content into web pages, redirecting users to phishing sites or distributing malware. The scope of the impact can range from individual users to entire organizations, depending on the extent of the compromise.

## Recommendation

*   Enable Sysmon Event ID 11 (File Create) logging to capture the necessary file creation events for this detection.
*   Deploy the provided Sigma rule `Browser Extension Install via File Creation` to your SIEM and tune the exclusions for your specific environment.
*   Review and update the list of known safe processes and extensions in the Sigma rule `Browser Extension Install via File Creation` to minimize false positives.
*   Implement application whitelisting policies to restrict the installation of unauthorized browser extensions.
*   Educate users on the risks associated with installing browser extensions from untrusted sources and encourage them to only install extensions from official browser stores.
*   Implement policies to regularly review installed browser extensions across the organization.
