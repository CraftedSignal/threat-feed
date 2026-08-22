---
title: Zbtlink Router Firmware Contains Embedded ENDLESSDOORS Implant
slug: 2026-08-zbtlink-endlessdoors-implant
description: Zbtlink router firmware ships with the ENDLESSDOORS remote-control implant, which runs as root, masquerades as a kernel process, and enables unauthenticated remote command execution.
date: "2026-08-05T13:16:19Z"
lastmod: "2026-08-22T05:42:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=595891B8-C311-5C6A-9220-0544676F9FDF&utm_source=rss&utm_medium=rss
tags:
  - supply-chain
  - firmware
  - backdoors
  - remote-access-trojan
  - network-security
vendors:
  - Zbtlink
  - Wiflyer
products:
  - Router Firmware
  - CPE2801
  - WE1026-5G-WD
  - WE1326
  - WE2007
  - WE2008-DSIM
  - WE2416
  - WE3326
  - WE5927
  - WE5931
  - WE5931AC
  - WE826-T3-DSIM
  - WG108
  - WG209
  - WG259
  - WG1602
  - WG1608-DSIM
  - WG2105
  - WG2107
  - WG3526
  - ZBT-Z8102AX-2SIM
affected_os:
  - OpenWrt
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543.002
    technique_name: 'Create or Modify System Process: Systemd Service'
    evidence: It is the open-source ycsunjane/rctl tool built in as an OpenWrt package (librctl.so), started at boot and run as root
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Its command handler passes any received string to popen() as uid=0, and a reserved rctlbash command returns an interactive root shell
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
    evidence: It opens no listening port; it phones home over cleartext TCP to a hardcoded command-and-control server
    confidence_band: high
cves:
  - id: CVE-2026-66747
    cvss: 9.8
    epss: 0.00579
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66747
  - https://sploitus.com/exploit?id=595891B8-C311-5C6A-9220-0544676F9FDF&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate all identified Zbtlink devices from internal networks.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-66747 indicates firmware-level backdoors.
  mitigation_plan:
    - priority: immediate
      action: Block all outbound traffic on TCP ports 7000 and 7001 at the network perimeter.
      owner: IT Operations
      addresses: CVE-2026-66747
      evidence: Source document identifies these ports as the C2 communication channel.
updates:
  - at: "2026-08-22T05:42:51Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=595891B8-C311-5C6A-9220-0544676F9FDF&utm_source=rss&utm_medium=rss
---

Zbtlink router firmware across its entire product line contains an embedded remote-control implant identified as ENDLESSDOORS. This implant is derived from the open-source tool 'rctl' and is integrated as a persistent OpenWrt package (librctl.so). The malware masquerades as a legitimate system process, running as root under the name 'kworker' to mimic kernel worker threads and evade detection by basic process monitors. 

The implant operates via an unauthenticated, cleartext command-and-control (C2) channel that initiates an outbound callback approximately every 35 seconds. It does not open a listening port, opting instead for a phone-home architecture that uses hardcoded C2 communication parameters for both command handling (port 7000) and interactive shell sessions (port 7001). Because the communication lacks both authentication and transport encryption, any third party capable of intercepting the network path or hijacking the C2 domain can gain full root-level remote code execution on the affected devices by issuing commands via popen() or the specific 'rctlbash' command.

## Attack Chain

1. The ENDLESSDOORS implant, bundled as 'librctl.so', is initialized automatically at system boot via firmware-level configuration.
2. The process is spawned with root privileges and renamed to 'kworker' to obfuscate its presence among legitimate kernel threads.
3. The implant periodically polls for C2 instructions by initiating outbound cleartext TCP connections on ports 7000 and 7001 every 35 seconds.
4. An attacker intercepts the cleartext outbound traffic or redirects DNS queries to a malicious server mimicking the hardcoded C2 infrastructure.
5. The attacker sends a command string to the implant over the unauthenticated TCP stream.
6. The implant's command handler processes the received string using popen() with root (uid=0) permissions.
7. The attacker issues the 'rctlbash' command to spawn a reverse interactive root shell to the attacker's machine.
8. Full persistent remote administrative control is achieved on the router, facilitating further network lateral movement.

## Impact

The vulnerability affects all Zbtlink router firmware builds currently in deployment. Successful exploitation allows an attacker to achieve unauthenticated remote code execution with root privileges. Given the nature of these devices acting as network gateways, this impact enables total traffic interception, credential harvesting, and long-term persistence within the affected local networks.

## Recommendation

* Monitor egress traffic from network hardware for cleartext TCP connections on ports 7000 and 7001.
* Identify and isolate Zbtlink routers within the network, as they are inherently compromised by firmware design.
* Implement strict firewall egress rules at the network perimeter to block all communication to unrecognized or non-essential external IP addresses from router management interfaces.
* Audit process lists on managed OpenWrt devices for any 'kworker' instances that exhibit unexpected socket connections or that do not correlate with kernel-level thread activity.
