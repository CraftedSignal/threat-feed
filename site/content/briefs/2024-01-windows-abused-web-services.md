---
title: Windows Hosts Querying Abused Web Services
slug: 2024-01-windows-abused-web-services
description: Adversaries may use abused web services such as paste sites, VoIP, and file hosting to host malicious payloads or facilitate command and control, detected via DNS queries from Windows hosts to these services.
date: "2024-01-03T15:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - abused-web-service
  - command-and-control
  - initial-access
  - windows
vendors:
  - GitHub
  - Dropbox
  - NGROK
  - Cloudflare
  - Google
products:
  - githubusercontent.com
  - anonfiles.com
  - argotunnel.com
  - cdn.discordapp.com
  - ddns.net
  - dl.dropboxusercontent.com
  - duckdns.org
  - ghostbin.co
  - glitch.me
  - gofile.io
  - hastebin.com
  - mediafire.com
  - mega.nz
  - ngrok.io
  - onrender.com
  - pages.dev
  - paste.ee
  - pastebin.com
  - pastebin.pl
  - pasteio.com
  - pastetext.net
  - privatlab.com
  - privatlab.net
  - send.exploit.in
  - sendspace.com
  - storage.googleapis.com
  - storjshare.io
  - supabase.co
  - temp.sh
  - textbin
  - transfer.sh
  - trycloudflare.com
  - ufile.io
  - w3spaces.com
  - workers.dev
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat
  - https://github.com/splunk/security_content/blob/main/detections/network/windows_abused_web_services.yml
iocs:
  - type: domain
    value: objects.githubusercontent.com
  - type: domain
    value: anonfiles.com
  - type: domain
    value: argotunnel.com
  - type: domain
    value: cdn.discordapp.com
  - type: domain
    value: ddns.net
  - type: domain
    value: dl.dropboxusercontent.com
  - type: domain
    value: duckdns.org
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
    value: ngrok.io
  - type: domain
    value: onrender.com
  - type: domain
    value: pages.dev
  - type: domain
    value: paste.ee
  - type: domain
    value: pastebin.com
  - type: domain
    value: pastebin.pl
  - type: domain
    value: pasteio.com
  - type: domain
    value: pastetext.net
  - type: domain
    value: privatlab.com
  - type: domain
    value: privatlab.net
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
  domain: 34
rules:
  - title: Detect Windows Abused Web Services DNS Queries
    description: Detects DNS queries to known abused web services from Windows hosts.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102
    data_sources:
      - dns_query
      - windows
  - title: Detect Process Accessing Abused Web Services
    description: Detects processes making network connections to known abused web services.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This threat brief highlights the abuse of legitimate web services by threat actors to host and distribute malicious content, as well as to facilitate command and control (C2) activities. The activity is identified through DNS queries originating from Windows hosts to a list of known, abused web services, including paste sites (e.g., Pastebin), file hosting services (e.g., Mediafire), and cloud platforms (e.g., Cloudflare Workers). This technique allows attackers to evade traditional network-based detections by leveraging the reputation and infrastructure of these legitimate services. Detection is based on Sysmon Event ID 22 (DNS Query) logs. This is significant as it may indicate initial access, command and control or lateral movement within the network.

## Attack Chain

1. A user on a Windows host inadvertently clicks a malicious link or opens a compromised document.
2. The malicious content triggers a process (e.g., PowerShell, cmd.exe) to execute.
3. The executed process initiates a DNS query to a known, abused web service (e.g., pastebin.com, mega.nz) using Windows DNS client.
4. The DNS query resolves to the IP address of the web service hosting the malicious payload or C2 instructions.
5. The process establishes a network connection (HTTP/HTTPS) to the resolved IP address to download a file or receive commands.
6. The downloaded file is saved to disk or executed directly in memory.
7. The executed payload performs malicious activities, such as establishing persistence, exfiltrating data, or deploying additional malware.

## Impact

Successful exploitation can lead to the initial compromise of a system, allowing attackers to establish a foothold within the network. This can result in data theft, deployment of ransomware, or further propagation of the attack to other systems on the network. Identifying systems making these queries can help identify compromised systems and prevent further damage.

## Recommendation

*   Enable Sysmon DNS query logging (Event ID 22) to capture DNS requests for external domains.
*   Deploy the Sigma rule `Detect Windows Abused Web Services DNS Queries` to your SIEM and tune for your environment.
*   Monitor network traffic for connections to the domains listed in the IOC table and investigate any suspicious activity.
*   Implement network segmentation to limit the impact of a compromised host.
*   Block the C2 domains listed in the IOC table at the DNS resolver.
