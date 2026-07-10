---
title: Suspicious File Download via Headless Browser
slug: 2024-01-headless-browser-download
description: Attackers are leveraging Chromium-based browsers in headless mode with the `--dump-dom` argument to download files from file-sharing services and direct IPs, potentially indicative of reconnaissance or malware delivery.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - headless-browser
  - file-download
  - cisco-nvm
vendors:
  - Google
  - Microsoft
  - Brave Software
products:
  - Chrome
  - Edge
  - Brave Browser
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://labs.withsecure.com/content/dam/labs/docs/WithSecure_Research_DUCKTAIL.pdf
  - https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html
  - https://x.com/mrd0x/status/1478234484881436672?s=12
  - https://developer.chrome.com/docs/chromium/headless
iocs:
  - type: domain
    value: '*.githubusercontent.com*'
  - type: domain
    value: '*anonfiles.com*'
  - type: domain
    value: '*cdn.discordapp.com*'
  - type: domain
    value: '*ddns.net*'
  - type: domain
    value: '*dl.dropboxusercontent.com*'
  - type: domain
    value: '*ghostbin.co*'
  - type: domain
    value: '*glitch.me*'
  - type: domain
    value: '*gofile.io*'
  - type: domain
    value: '*hastebin.com*'
  - type: domain
    value: '*mediafire.com*'
  - type: domain
    value: '*mega.nz*'
  - type: domain
    value: '*onrender.com*'
  - type: domain
    value: '*pages.dev*'
  - type: domain
    value: '*paste.ee*'
  - type: domain
    value: '*pastetext.net*'
  - type: domain
    value: '*send.exploit.in*'
  - type: domain
    value: '*sendspace.com*'
  - type: domain
    value: '*storage.googleapis.com*'
  - type: domain
    value: '*storjshare.io*'
  - type: domain
    value: '*supabase.co*'
  - type: domain
    value: '*temp.sh*'
  - type: domain
    value: '*transfer.sh*'
  - type: domain
    value: '*trycloudflare.com*'
  - type: domain
    value: '*ufile.io*'
  - type: domain
    value: '*w3spaces.com*'
  - type: domain
    value: '*workers.dev*'
ioc_counts:
  domain: 26
rules:
  - title: Headless Browser with Dump-DOM Argument
    description: Detects Chromium-based browsers running in headless mode with --dump-dom argument.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Network Connection to File Sharing Services from Headless Browser
    description: Detects network connections from Chromium-based browsers running in headless mode to known file-sharing services.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Attackers are increasingly utilizing Chromium-based browsers such as Chrome, Edge, and Brave in headless mode to download files surreptitiously. This technique involves using the `--headless` and `--dump-dom` arguments, allowing attackers to automate browser actions without a graphical user interface. This tactic has been observed in campaigns like DUCKTAIL, where attackers used this method to download content from the internet using direct URLs or file-sharing platforms. This behavior is especially concerning because it can bypass traditional security measures that rely on user interaction. Defenders should be aware of processes spawning headless browsers and monitor for network connections to file-sharing services or unusual IP addresses.

## Attack Chain

1.  The attacker compromises a system through an initial access vector (e.g., spearphishing, exploit).
2.  The attacker executes a Chromium-based browser (Chrome, Edge, Brave, etc.) from the command line or through a script.
3.  The browser is launched with the `--headless` and `--dump-dom` arguments to run without a GUI and potentially download content.
4.  The attacker uses the browser to access a URL, either a direct IP address or a file-sharing service like Mega.nz or Mediafire.com.
5.  The browser downloads a file from the specified URL or domain.
6.  The downloaded file may be a malicious payload, configuration file, or stolen data.
7.  The attacker executes the downloaded file or uses the data for further exploitation or lateral movement.

## Impact

A successful attack can lead to malware infection, data exfiltration, or further compromise of the affected system and network. The use of headless browsers makes detection more challenging, as it mimics legitimate browser activity without the visual cues of a typical user session. The number of victims and specific sectors targeted are currently unknown, but the potential for widespread impact is significant, especially if the downloaded files contain ransomware or other destructive payloads.

## Recommendation

*   Monitor process creation events for Chromium-based browsers (chrome.exe, msedge.exe, brave.exe) with the `--headless` and `--dump-dom` arguments using the provided Sigma rules.
*   Inspect network connections from processes matching the above criteria to known file-sharing domains listed in the IOCs.
*   Analyze command-line arguments of browser processes for direct IP addresses and correlate with network connection logs.
*   Review the `known_false_positives` section in the original Splunk detection for tips on tuning the detections.
