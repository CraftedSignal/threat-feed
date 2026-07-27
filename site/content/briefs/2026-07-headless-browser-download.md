---
title: Suspicious File Download via Headless Browser
slug: 2026-07-headless-browser-download
description: The DUCKTAIL threat actor leverages Chromium-based web browsers (such as Microsoft Edge and Chrome) running in headless mode with the `--dump-dom` argument to stealthily download malicious content from the internet via suspicious file-sharing domains, impacting compromised endpoints.
date: "2026-07-27T18:10:39Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - DUCKTAIL
tags:
  - headless-browser
  - file-download
  - data-exfiltration
  - malware-delivery
  - endpoint
  - network
vendors:
  - Brave
  - Google
  - Microsoft
  - Opera
  - Vivaldi Technologies
products:
  - Brave Browser
  - Google Chrome
  - Microsoft Edge
  - Opera Browser
  - Vivaldi Browser
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This analytic identifies the use of Chromium-based browsers (like Microsoft Edge) running in headless mode with the `--dump-dom` argument.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This behavior has been observed in attack campaigns such as DUCKTAIL, where browsers are automated to stealthily download content from the internet using direct URLs or suspicious hosting platforms.
    confidence_band: high
references:
  - https://labs.withsecure.com/content/dam/labs/docs/WithSecure_Research_DUCKTAIL.pdf
  - https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html
  - https://x.com/mrd0x/status/1478234484881436672?s=12
  - https://developer.chrome.com/docs/chromium/headless
iocs:
  - type: domain
    value: githubusercontent.com
  - type: domain
    value: anonfiles.com
  - type: domain
    value: cdn.discordapp.com
  - type: domain
    value: ddns.net
  - type: domain
    value: dl.dropboxusercontent.com
  - type: domain
    value: ghostbin.co
  - type: domain
    value: glitch.me
  - type: domain
    value: gofile.io
  - type: domain
    value: hastebin.com
  - type: domain
    value: mediafire.com
  - type: domain
    value: mega.nz
  - type: domain
    value: onrender.com
  - type: domain
    value: pages.dev
  - type: domain
    value: paste.ee
  - type: domain
    value: pastetext.net
  - type: domain
    value: send.exploit.in
  - type: domain
    value: sendspace.com
  - type: domain
    value: storage.googleapis.com
  - type: domain
    value: storjshare.io
  - type: domain
    value: supabase.co
  - type: domain
    value: temp.sh
  - type: domain
    value: transfer.sh
  - type: domain
    value: trycloudflare.com
  - type: domain
    value: ufile.io
  - type: domain
    value: w3spaces.com
  - type: domain
    value: workers.dev
ioc_counts:
  domain: 26
rules:
  - title: Detect Suspicious File Download via Headless Chromium Browser
    description: Detects Chromium-based browsers (Edge, Chrome, Brave, Opera, Vivaldi) running in headless mode with `--dump-dom` argument, connecting to suspicious file-sharing or hosting domains, a technique observed in DUCKTAIL campaigns.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1105
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

Since at least 2025, the DUCKTAIL threat actor has been observed utilizing a deceptive technique involving headless Chromium-based browsers like Microsoft Edge, Google Chrome, Brave, Opera, and Vivaldi. This method automates the download of content from suspicious internet sources using direct URLs or known file-sharing platforms. By launching browsers in `--headless` mode and employing the `--dump-dom` argument, DUCKTAIL aims to covertly retrieve additional tools, malware, or sensitive data onto compromised systems without visual user interaction. This tactic enables attackers to maintain a low profile while escalating their control or exfiltrating information, making detection challenging without specific network and process monitoring. The technique relies on the browser's ability to render web content and dump its Document Object Model, which can be leveraged to retrieve various file types.

## Attack Chain

1. An attacker's tool or script executes a Chromium-based web browser (e.g., `chrome.exe`, `msedge.exe`, `brave.exe`, `opera.exe`, `vivaldi.exe`) on a compromised endpoint.
2. The browser is launched with specific command-line arguments, including `--headless`, indicating it should run without a visible user interface.
3. The `--dump-dom` command-line argument is supplied to the browser, instructing it to render a specified URL and output its Document Object Model, which can be used to capture or retrieve content.
4. The headless browser initiates an outbound network connection to a specified malicious URL or a suspicious file-sharing domain (e.g., `anonfiles.com`, `cdn.discordapp.com`, `githubusercontent.com`).
5. The browser stealthily downloads content from the remote server, which may include malware, additional stage tools, or files for exfiltration.
6. The downloaded content is then utilized for subsequent phases of the DUCKTAIL campaign, such as credential harvesting, data exfiltration, or further system compromise.

## Impact

Successful exploitation allows attackers, such as DUCKTAIL, to download additional malicious payloads, maintain persistence, exfiltrate sensitive data, or install infostealers. The stealthy nature of this technique makes it difficult for users to detect, potentially leading to prolonged compromise and significant data breaches. DUCKTAIL campaigns have historically targeted individuals and businesses, primarily focusing on information theft, especially credentials for social media and business platforms, leading to financial fraud and intellectual property theft.

## Recommendation

* Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect suspicious headless browser activity.
* Ensure Cisco Network Visibility Module logs are collected and ingested into your SIEM platform to facilitate detection based on network flow data.
* Implement network egress filtering to block connections to the suspicious file-sharing domains listed in the IOC table.
* Monitor process creation and command-line arguments for browser executables to identify `--headless` and `--dump-dom` usage from unexpected processes or user contexts.
