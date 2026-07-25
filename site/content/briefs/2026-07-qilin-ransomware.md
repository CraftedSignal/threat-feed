---
title: Qilin Ransomware Claims New Victim in Agriculture and Food Production Sector
slug: 2026-07-qilin-ransomware
description: The Qilin ransomware group, active since July 2022 and utilizing Golang, has claimed a new victim, Danone (International Delights) in the US Agriculture and Food Production sector, employing double extortion tactics involving data encryption and threatened data release.
date: "2026-07-15T20:00:29Z"
lastmod: "2026-07-25T12:01:52Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - Qilin
  - Agenda
tags:
  - ransomware
  - qilin
  - double-extortion
  - golang
  - agriculture
  - food-production
vendors:
  - Acosol
  - VMware
  - Carbon Black
  - Toshiba
  - Powder River Heating
  - Martorani
  - NetSupport
  - ScreenConnect
  - Zemana
  - Cityambu
  - Famesa
  - Apache
  - Fortinet
  - SmarterTools
  - Telnet
  - WatchGuard
  - Check Point
  - Veeam
  - SolarWinds
  - RehaVital Gesundheitsservice GmbH
  - GNU
  - EZ Systems
  - MEGA
  - Qilin
  - GNU Inetutils
  - Triton
  - API
  - Microsoft
products:
  - www.acosol.es
  - vCenter
  - ESXi
  - Cloud Sensor AV
  - VMware vCenter
  - VMware ESXi
  - Carbon Black Cloud Sensor AV
  - Toshiba power management driver
  - NetSupport
  - ScreenConnect
  - Zemana Anti-Rootkit driver
  - www.nuevaschool.org
  - Apache bRPC
  - FortiOS
  - FortiProxy
  - SmarterMail
  - Telnetd in GNU Inetutils
  - WatchGuard Fireware OS
  - Check Point VPN Remote Access and Mobile Access
  - Veeam Backup & Replication
  - SolarWinds Web Help Desk
  - Zemana AntiLogger
  - VPN Remote Access and Mobile Access
  - Backup & Replication
  - www.rehavital.de
  - EasyUpload.io
  - MEGA
  - VPN Remote Access
  - Mobile Access
  - www.triton.com.pe
  - www.api.com.ph
  - Telnetd
  - Fireware OS
  - Web Help Desk
  - AntiLogger
  - vCenters
  - FortiOS & FortiProxy
affected_os:
  - Windows
  - Unix
  - Linux
  - ESXi
  - VMware ESXi
  - FortiOS
  - WatchGuard Fireware OS
  - Fireware OS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Phishing
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Valid Accounts
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Command and Scripting Interpreter: PowerShell'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: 'Scheduled Task/Job: Scheduled Task'
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: 'OS Credential Dumping: LSASS Memory'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: 'Impair Defenses: Disable or Modify System Firewall'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Network Service Discovery
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: 'Remote Services: SMB/Windows Admin Shares'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
    evidence: 'Archive Collected Data: Archive via Utility'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: 'Exfiltration Over Web Service: Exfiltration to Cloud Storage'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: 'Application Layer Protocol: Web Protocols'
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Data Encrypted for Impact
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Inhibit System Recovery
    confidence_band: high
references:
  - https://www.ransomware.live/group/qilin
  - https://www.secureworks.com/research/threat-profiles/gold-feather
  - https://www.trendmicro.com/en_us/research/24/c/agenda-ransomware-propagates-to-vcenters-and-esxi-via-custom-pow.html
  - https://cloud.google.com/blog/topics/threat-intelligence/unc3944-sms-phishing-sim-swapping-ransomware/
  - https://www.trendmicro.com/en_us/research/22/h/new-golang-ransomware-agenda-customizes-attacks.html
iocs:
  - type: domain
    value: www.idelights.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=2a85afa5-7c66-4fe2-a552-df3f6954cb9c
  - type: domain
    value: ozsxj4hwxub7gio347ac7tyqqozvfioty37skqilzo2oqfs4cw2mgtyd.onion
  - type: domain
    value: kbsqoivihgdmwczmxkbovk7ss2dcynitwhhfu5yw725dboqo5kthfaad.onion
  - type: domain
    value: ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion
  - type: domain
    value: ji57fr53anp7wb44tbbnp72qcgbhqywy4jmbncawdcrejj5amuvh3zqd.onion
  - type: hash_md5
    value: 08a2405cd32f044a69737e77454ee2da
  - type: hash_md5
    value: 0d68a310f4265821900249bec89364c2
  - type: hash_md5
    value: 11d795baafa44b73766e850d13b8e254
  - type: hash_md5
    value: 144183a4217ae0914ba0c865858d07cd
  - type: hash_md5
    value: 19ff6488a259d750ec18902fe75a713b
  - type: hash_md5
    value: 1bde76f3197123dcc2ecd0bfef567484
  - type: hash_md5
    value: 1c4bea81c0da22badd9b7eab574c51cd
  - type: hash_md5
    value: 2020979e080d7ac9c0403172573c7de8
  - type: hash_md5
    value: 24a8fcd08d9e40d32929b57de9b15385
  - type: hash_md5
    value: 2bb209ccfc5103eccab523c875050cfa
  - type: hash_md5
    value: 2f76a29d4e4292d7f29a29345717812c
  - type: hash_md5
    value: 3158a3849ea2695d6ec5aea6512fd030
  - type: hash_md5
    value: 348b0ce6af4698061678c8e92b4b2675
  - type: hash_md5
    value: 37155f0bca29ccd6b6d4f5b2bc42eb4d
  - type: hash_md5
    value: 3b10127e65fa3e215d21e0a2e7fd32be
  - type: hash_md5
    value: 417ad60624345ef85e648038e18902ab
  - type: hash_md5
    value: 420a2c53386678396f972f09cc7f3a5c
  - type: hash_md5
    value: 4a3f22021e4415e8211633fb3735a046
  - type: hash_md5
    value: 4ea8adecc5bd45a76cc61430c560924f
  - type: hash_md5
    value: 53c8a4f0497929de4a5039b2c14bf426
  - type: hash_md5
    value: 575b26c1cc06609722f98e2beaed6a8a
  - type: hash_md5
    value: 5862f9fc9c9a0d766eba29eb4945f619
  - type: hash_md5
    value: 59d756280b06cf113ca43abc0050edd5
  - type: hash_md5
    value: 5cffa3126b9effc279d32b2cf4ef2278
  - type: hash_md5
    value: 64a590760fdbb84356544cc90ac3d50f
  - type: hash_md5
    value: 670fe8faaede4e2e033311fb662d2a4a
  - type: hash_md5
    value: 6f893b1cc5cf534c59eabe932c1bf21e
  - type: hash_md5
    value: 6fc6164b3a08669992acad3764fb1922
  - type: hash_md5
    value: 826a8e8c05983aa3a884d7abcfa473ac
  - type: hash_md5
    value: 88630916b0c6633ca28c8896416a93ee
  - type: hash_md5
    value: 88bb86494cb9411a9692f9c8e67ed32c
  - type: hash_md5
    value: 8ca5c9745e8a0e18167a9b932821645a
  - type: hash_md5
    value: 964c13b68dc6b6b918b66a9a10469d2a
  - type: hash_md5
    value: 996c394d0f6d6967df9542c52f6f4661
  - type: hash_md5
    value: 9befad1d56d2bd8195813aea1f37f921
  - type: hash_md5
    value: 9ea321b6a0f069caab7092cfe1cbbde0
  - type: hash_md5
    value: 9f510626c7327a7c2328bc5131726638
  - type: hash_md5
    value: a6302fdb63e2244c1246a73a7d65d09e
  - type: hash_md5
    value: a7ab0969bf6641cd0c7228ae95f6d217
  - type: hash_md5
    value: a7e7d00d531cb7ca27d0f3bee448573f
  - type: hash_md5
    value: ab05a1925fee8334a2114811d5283364
  - type: hash_md5
    value: b04e8ee43aba85fa5c585b9335c953c2
  - type: hash_md5
    value: b4a6152514919a637c22a58bea316fc7
  - type: hash_md5
    value: bed0f34673cc93560c17e3ab04ea5d19
  - type: hash_md5
    value: d1c331c17ddd4abe0d53755461c1ec9a
  - type: hash_md5
    value: d309e3d77ed6a336eb3ad263ddf9db90
  - type: hash_md5
    value: d6e7547ad7dfd1fbc62e8282aebcc391
  - type: hash_md5
    value: dd42c3e017889c107a81da78d87dc8af
  - type: hash_md5
    value: e01776ec67b9f1ae780c3e24ecc4bf06
  - type: hash_md5
    value: e4c1add9f7606e3fa57976b908b4b375
  - type: hash_md5
    value: ea1f8794c73b26724314e5356f1f4128
  - type: hash_md5
    value: f588802958c35fe18eb87bc36651a3d1
  - type: hash_md5
    value: f982da00c547913fd0ae7d0da0fc77e7
  - type: hash_md5
    value: fdc6848dad660414bed9ad1b381cf6e3
  - type: ip
    value: 176.113.115.209
  - type: ip
    value: 176.113.115.97
  - type: ip
    value: 188.119.66.189
  - type: ip
    value: 31.41.244.100
  - type: ip
    value: 85.209.11.49
  - type: domain
    value: www.acosol.es
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=06db273a-dad1-49d1-98ea-f59c947de0b6
  - type: domain
    value: www.cafar.org.ar
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=534f0ef4-d3fb-4650-ae42-445c281986c6
  - type: domain
    value: www.powderriverheating.com
  - type: domain
    value: www.martorani.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=7e150d05-bd34-404d-8824-a10358840d67
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=cddad5ee-72f3-48fd-9310-4858484d5f59
  - type: domain
    value: www.akpreparedness.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=ce1a0a64-9560-4bbf-8489-b0af28ec8fad
  - type: domain
    value: www.sicc-srl.com
  - type: domain
    value: www.kldlabs.com
  - type: domain
    value: www.armara.fr
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/
  - type: domain
    value: www.nuevaschool.org
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=f5d63ec4-a191-4de4-a6d1-f0fa52fba59e
  - type: domain
    value: www.cityambu.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=9a5b2562-d3a3-4b7a-b2fa-2624534ed258
  - type: domain
    value: www.famesa.com.pe
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=319f4978-5d69-49df-a821-e9debceb58af
  - type: domain
    value: www.dontortaco.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=41fcdb99-7cf5-4296-9690-fc9938f213c0
  - type: domain
    value: www.associatedtheatrical.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=d5df444b-e533-4535-9797-08f40baf4f0b
  - type: domain
    value: www.uniteppk.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=50585917-0d64-434d-86be-6145703b6ec3
  - type: domain
    value: www.eana.com.ar
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=ea827c06-3e50-4215-b031-385307e23c22
  - type: domain
    value: www.synergy-trt.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=1b6eeb3c-9231-44bf-ab8b-16c3eb7e2284
  - type: domain
    value: www.bnml.co.uk
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=055bff03-344a-4bdb-901b-6b98520d47cd
  - type: domain
    value: www.postresreina.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=48655caf-4585-42fd-9ab0-386475bc0c00
  - type: domain
    value: www.rehavital.de
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=0a73be27-9f34-45d8-b63d-c4a0a0157f9d
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=3a2be923-3c7d-48b9-aa44-380fc15b5215
  - type: domain
    value: www.cpcgr.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=d5db2e06-b2a3-405f-8354-3783d5e308a1
  - type: domain
    value: www.salida.k12.ca.us
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=faf2030b-b0df-4f52-98f9-3931b91b2ad1
  - type: domain
    value: www.paconst.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=e3c69462-969a-4bfd-8992-06497d92921c
  - type: domain
    value: www.sunway.com.my
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=29c74989-187f-43cd-a8bf-c3d3adfd8b78
  - type: domain
    value: www.triton.com.pe
  - type: domain
    value: www.api.com.ph
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=4e3a4d8c-18f4-4c90-9ae8-f0ce5e5b4240
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=b270fcbc-a829-4d7e-8261-079a785eb8c6
  - type: domain
    value: www.wellperf.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=e03a3141-5643-405c-98b0-29735f95c049
  - type: domain
    value: www.machineriepw.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=68dd90a8-fe7d-405a-87c8-b8d660c18154
  - type: domain
    value: www.abmenviro.ca
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=9f71de4a-ee6f-4382-8148-85ab3c440fc4
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=9f76650e-5eea-4165-9e20-b375488e9ec6
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=67e53658-cf53-4b9d-a2df-a6b7a9361416
  - type: hash_md5
    value: 5862f9fc9a9a0d766eba29eb4945f619
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=9a5d858f-7849-458c-8762-abd073fbbb0c
  - type: domain
    value: www.gopltd.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=bb832c6c-99a5-48b5-a604-526591d752bd
  - type: domain
    value: www.principlediagnostics.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=5179ba1b-2046-4654-854b-eafbce6e6029
  - type: domain
    value: www.guntert.com
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=fe0866f0-5661-4013-be19-98c2a0c1dfc6
ioc_counts:
  domain: 36
  hash_md5: 55
  ip: 5
  url: 34
rules:
  - title: Detect Qilin Ransomware Hashes
    description: Detects known Qilin ransomware samples by their MD5 hashes, indicative of malware presence on the system.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - file_event
      - windows
  - title: Detect Qilin C2 Network Connections
    description: Detects outbound network connections to known Qilin ransomware command-and-control (C2) infrastructure IP addresses or unusual FTP connections for data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1041
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
updates:
  - at: "2026-07-24T10:43:36Z"
    level: L1
    summary: OS fireware os
    sources:
      - ransomware-live
    source_urls:
      - https://www.ransomware.live/group/qilin
  - at: "2026-07-24T11:39:05Z"
    level: L1
    summary: new IOCs
    sources:
      - ransomware-live
    source_urls:
      - https://www.ransomware.live/group/qilin
  - at: "2026-07-24T23:08:47Z"
    level: L1
    summary: new IOCs
    sources:
      - ransomware-live
    source_urls:
      - https://www.ransomware.live/group/qilin
  - at: "2026-07-25T11:39:21Z"
    level: L1
    summary: new IOCs
    sources:
      - ransomware-live
    source_urls:
      - https://www.ransomware.live/group/qilin
  - at: "2026-07-25T12:01:52Z"
    level: L1
    summary: new IOCs
    sources:
      - ransomware-live
    source_urls:
      - https://www.ransomware.live/group/qilin
---

The Qilin ransomware group, a highly active threat actor first observed in July 2022, continues its double extortion operations, with a recent claim against Danone (International Delights), a US-based company in the Agriculture and Food Production sector. Qilin ransomware is written in Golang, offering multiple encryption modes controlled by the operators, and its campaigns typically involve both data encryption and the threat of public release of stolen sensitive information if a ransom is not paid. The group has accumulated over 2000 victims across various industries, including manufacturing, business services, technology, and healthcare, primarily targeting entities in the United States. This ongoing activity highlights Qilin's persistent threat to critical infrastructure and diverse commercial enterprises globally.

## Attack Chain

1. **Initial Access**: Attackers gain entry through various methods, including the exploitation of public-facing applications, spearphishing via email, or leveraging valid but compromised accounts (e.g., T1566, T1190, T1078).
2. **Execution**: Qilin operators execute malicious code using scripting interpreters like PowerShell or Unix Shell, or by deploying malicious system services (e.g., T1059.001, T1059.004, T1569.002).
3. **Persistence & Privilege Escalation**: Persistence is established via scheduled tasks or boot/logon autostart execution. Privilege escalation is achieved through exploitation of vulnerabilities or techniques like OS credential dumping (e.g., T1053.005, T1547, T1068, T1003.001).
4. **Defense Evasion**: The group employs techniques such as obfuscated files, modifying or disabling security tools, and impairing system defenses like firewalls to maintain access and avoid detection (e.g., T1027, T1562, T1562.004).
5. **Discovery & Lateral Movement**: Attackers conduct extensive network reconnaissance, querying registries, sniffing network traffic, and using remote services (e.g., SMB/Windows Admin Shares, RDP) to identify high-value targets and move laterally across the compromised network (e.g., T1012, T1046, T1021.001, T1021.002).
6. **Collection & Exfiltration**: Sensitive data is collected and often archived using utilities before being exfiltrated over alternative network mediums or to cloud storage services (e.g., T1560.001, T1041, T1567.002).
7. **Command and Control**: Communication with C2 infrastructure is maintained through various methods, including obfuscated data and tunneling over common application layer protocols like web protocols (e.g., T1001, T1071.001, T1572).
8. **Impact**: The final stage involves encrypting victim data, inhibiting system recovery mechanisms, and sometimes wiping disks to maximize disruption and coerce ransom payment (e.g., T1486, T1490, T1488, T1488.001).

## Impact

The Qilin ransomware group's attacks result in severe operational disruption, data loss due to encryption, and potential public exposure of sensitive information through their double extortion model. With over 2000 victims reported since 2022, including a recent target in the US Agriculture and Food Production sector, the scope of their impact is significant and spans diverse industries like manufacturing, business services, technology, and healthcare. Successful attacks lead to direct financial losses from ransom demands, costs associated with incident response and recovery, and severe reputational damage. The loss of critical business data and systems can halt operations for extended periods, impacting supply chains and essential services.

## Recommendation

* Implement endpoint detection and response (EDR) solutions to detect and block malicious hashes listed in the IOCs.
* Block connections to the malicious IP addresses and domains listed in the IOC table at the network perimeter firewall and DNS resolver.
* Deploy and tune endpoint security rules, such as the `Detect Qilin Ransomware Hashes` rule, to identify and quarantine known Qilin ransomware samples.
* Implement and continuously monitor the `Detect Qilin C2 Network Connections` rule to identify and alert on suspicious outbound network activity to known Qilin infrastructure.
* Enable comprehensive logging for process creation, network connections, and file events on all endpoints to provide visibility for the detection rules and facilitate incident response.
* Review and enforce strong password policies and multi-factor authentication (MFA) to mitigate initial access attempts via valid accounts (ATT&CK T1078).
* Regularly patch and update all public-facing applications and systems to prevent exploitation of vulnerabilities (ATT&CK T1190).
