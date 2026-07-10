---
title: Windows Hosts Querying Abused Web Services
slug: 2024-11-abused-web-services
description: Suspicious processes on Windows hosts are making DNS queries to known, abused web services such as text-paste sites, file sharing platforms, and tunneling services, potentially indicating malware downloading or command and control activity.
date: "2024-11-01T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - abused-web-services
  - command-and-control
  - windows
vendors:
  - Microsoft
  - MediaFire
  - ngrok
  - Pastebin
products:
  - Microsoft Windows
  - Microsoft PowerShell
  - MediaFire
  - ngrok
  - Pastebin
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
  domain: 33
rules:
  - title: Detect DNS Queries to Known Abused Web Services
    description: Detects processes making DNS queries to domains associated with abused web services.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102
    data_sources:
      - dns_query
      - windows
  - title: Suspicious Process Accessing Abused Web Services
    description: Detects unusual processes making connections to abused web services
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

This threat brief highlights the use of legitimate web services for malicious purposes. Attackers often leverage these services to host malware, exfiltrate data, or establish command and control (C2) channels. This activity focuses on detecting suspicious processes making DNS queries to domains associated with services like pastebin.com, mediafire.com, and ngrok.io. These services are abused due to their widespread use and the trust often placed in them, making it easier for attackers to blend in with normal network traffic. The increased use of such services in malicious campaigns necessitates proactive detection and monitoring. The scope of targeting includes any Windows endpoint within an organization's network. This activity is commonly seen across various malware families.

## Attack Chain

1. A user clicks a malicious link or opens a compromised document (not directly observed in source).
2. The compromised document executes a malicious script, such as PowerShell, via `cmd.exe`.
3. The script initiates a DNS query to a known, abused web service, like `pastebin.com`, using Windows DNS client.
4. The attacker retrieves a payload or configuration from the web service via HTTP or HTTPS.
5. The script downloads and executes the payload in memory or on disk.
6. The payload establishes persistence and begins beaconing to a command-and-control server, potentially using `ngrok.io` for tunneling.
7. The attacker uses the C2 channel to send commands and exfiltrate sensitive data or deploy additional malware.
8. The attacker achieves their final objective, such as data theft, ransomware deployment, or system compromise.

## Impact

Successful exploitation can lead to various detrimental outcomes. Malware infections can disrupt business operations, resulting in financial losses and reputational damage. Data exfiltration can compromise sensitive information, leading to legal and regulatory penalties. Ransomware deployment can encrypt critical files, holding the organization hostage. The wide range of services abused makes detection challenging but crucial. The impact can range from a single compromised host to a full-scale network breach.

## Recommendation

*   Enable Sysmon Event ID 22 (DNS Query) logging to capture DNS query events (reference: description, search query).
*   Deploy the Sigma rules provided in this brief to your SIEM and tune them based on your environment's baseline (reference: rules).
*   Review and update firewall rules to restrict access to known abused web services if they are not required for business operations (reference: iocs).
*   Investigate any alerts generated by these rules to identify and remediate potentially compromised hosts (reference: rules).
