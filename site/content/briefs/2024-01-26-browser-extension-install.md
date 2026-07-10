---
title: Detection of Malicious Browser Extension Installation
slug: 2024-01-26-browser-extension-install
description: This rule detects the installation of browser extensions, a persistence mechanism where attackers install malicious extensions via app store downloads, social engineering, or compromised systems, focusing on file creation events in extension directories on Windows.
date: "2024-01-26T17:40:00Z"
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
  - Mozilla
  - Google
products:
  - Firefox
  - Chrome
references:
  - https://attack.mitre.org/techniques/T1176/
  - https://attack.mitre.org/techniques/T1176/001/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_browser_extension_install.toml
rules:
  - title: Detect Firefox Extension Installation via File Creation
    description: Detects the creation of new .xpi files in the Firefox extension directory, which could indicate a malicious browser extension installation.
    platform: sigma
    severity: low
    tactics:
      - persistence
    data_sources:
      - file_event
      - windows
  - title: Detect Chrome Extension Installation via File Creation
    description: Detects the creation of new .crx files in the Chrome extension download directory, indicating a potential malicious browser extension installation.
    platform: sigma
    severity: low
    tactics:
      - persistence
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection rule identifies the installation of browser extensions, a common persistence technique used by attackers. Malicious extensions can be installed via various methods, including masquerading as legitimate extensions on app stores, social engineering tactics, or direct installation on already compromised systems. The rule specifically focuses on monitoring file creation events within typical browser extension directories, primarily targeting Windows environments. It aims to filter out known safe processes and extensions to reduce false positives while effectively detecting potentially malicious installations. This is important for defenders because malicious browser extensions can be used for a variety of nefarious activities, including data exfiltration, session hijacking, and injecting malicious content into websites. The rule leverages file creation events and targets common extension file types such as `.xpi` for Firefox and `.crx` for Chrome-based browsers.

## Attack Chain

1.  The attacker gains initial access to the system, potentially through phishing or exploiting a software vulnerability.
2.  The attacker leverages their access to download or create a malicious browser extension file (`.xpi` or `.crx`).
3.  The malicious extension file is placed in a location that the browser will recognize as a valid extension source (e.g., user profile extension directory).
4.  The system logs a file creation event in the browser's extension directory (e.g., `?:\Users\*\AppData\Roaming\*\Profiles\*\Extensions\*.xpi` or `?:\Users\*\AppData\Local\*\*\User Data\Webstore Downloads\*`).
5.  The target browser detects the new extension file and installs it.
6.  The malicious extension gains access to the browser's APIs and user data, potentially allowing for data exfiltration or session hijacking.
7.  The attacker uses the installed extension for persistent access, maintaining a foothold even after system reboots.
8.  The attacker performs malicious activities such as injecting malicious code into websites, stealing credentials, or monitoring user browsing activity.

## Impact

A successful browser extension installation can lead to persistent access for attackers. Victims may experience data theft, credential compromise, or injection of malicious content into their browsing sessions. The scope of impact depends on the permissions granted to the extension and the data accessible through the browser. This can result in financial loss, reputational damage, and further compromise of systems and networks. Browser extensions can bypass traditional security controls, making them a valuable tool for attackers seeking persistence and stealth.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious browser extension installations, tuning for your environment to reduce false positives.
*   Enable Sysmon file creation logging to capture the events needed to activate the rules above.
*   Implement application whitelisting to prevent unauthorized browser extensions from being installed, focusing on the directories and file types identified in the detection query.
*   Educate users on safe browser extension installation practices to mitigate social engineering risks.
