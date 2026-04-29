---
title: Maltrail IOCs for Remcos RAT and EK_ClearFake
slug: 2026-02-maltrail-iocs
description: This brief summarizes IOCs related to Remcos RAT, a remote access trojan, and EK_ClearFake, an exploit kit, as identified by Maltrail on February 26, 2026.
date: "2026-02-26T17:00:11Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - remcos
  - clearfake
  - exploit-kit
  - rat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.circl.lu/doc/misp/feed-osint/9291457f-54be-4e1d-b239-3562e18112d7.json
  - https://api.github.com/repos/stamparm/maltrail/commits/0c6667175dd9fba7698bbf1bdf849297b605a2e3
  - https://x.com/BlinkzSec/status/2026899651345993936
  - https://www.virustotal.com/gui/file/4f0c95a1885411100649bf8150c2f189dc0941ac569b801b3765d1ca64b760dc/detection
  - https://api.github.com/repos/stamparm/maltrail/commits/210c5c1185382eb070ddcbbee197d498b2870bce
  - https://api.github.com/repos/stamparm/maltrail/commits/89ff2ed1d3a60e8ab5104cc8b6f398be6d6045ae
iocs:
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/0c6667175dd9fba7698bbf1bdf849297b605a2e3
  - type: url
    value: https://x.com/BlinkzSec/status/2026899651345993936
  - type: url
    value: https://www.virustotal.com/gui/file/4f0c95a1885411100649bf8150c2f189dc0941ac569b801b3765d1ca64b760dc/detection
  - type: ip
    value: 186.169.75.221
  - type: domain
    value: oficialrem.duckdns.org
  - type: domain
    value: filecindercrate.com
  - type: domain
    value: filedeltaforge.com
  - type: domain
    value: filemodulelink.com
  - type: domain
    value: filemonorailsync.com
  - type: domain
    value: fileoriginvault.com
  - type: domain
    value: filequartzrelay.com
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/210c5c1185382eb070ddcbbee197d498b2870bce
  - type: domain
    value: a.greetinggleeful.ru
  - type: domain
    value: greetinggleeful.ru
  - type: domain
    value: ns1.yyau.ru
  - type: domain
    value: s.greetinggleeful.ru
  - type: domain
    value: utterdeflected.ru
  - type: domain
    value: yyau.ru
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/89ff2ed1d3a60e8ab5104cc8b6f398be6d6045ae
  - type: domain
    value: 13nq2ksp.lunarbridge.digital
  - type: domain
    value: 1m89k7yv.primefusion.digital
  - type: domain
    value: 2lrej7f0.microzen.digital
  - type: domain
    value: 2z0nkkls.lumenbit.digital
  - type: domain
    value: 3li6xvqk.rapidmatrix.digital
  - type: domain
    value: 5mf4m58e.lumenbit.digital
  - type: domain
    value: 6u5wy3rf.lunarbridge.digital
  - type: domain
    value: 6ut6sdn1.clearvertex.digital
  - type: domain
    value: 85lgsf41.clearvertex.digital
  - type: domain
    value: activestatushub.snoozetrap.in.net
  - type: domain
    value: advancedsystrace.intricessaucy.in.net
  - type: domain
    value: aerospaceviewport.aircraftmodel.in.net
  - type: domain
    value: agri-tech-monitor.silverfield.ru
  - type: domain
    value: agricultural-monitoring.freshhill.ru
  - type: domain
    value: aidiyet.esb.org.tr
  - type: domain
    value: aircraftmodel.in.net
  - type: domain
    value: alphasync.digital
  - type: domain
    value: applicationbackup.implementnega.in.net
  - type: domain
    value: applynow.approvkrup.in.net
  - type: domain
    value: arctic-data-sync-node.thenorthernvertex.com
  - type: domain
    value: area-grove-sync.brightgrove.ru
  - type: domain
    value: atmospheric-sensor-unit.quietwind.ru
  - type: domain
    value: auditsounder.ru
  - type: domain
    value: authpoint.approvkrup.in.net
  - type: domain
    value: b113a978.alphasync.digital
  - type: domain
    value: b4svvivz.cybervox.digital
  - type: domain
    value: backgroundprocess.snoozetrap.in.net
  - type: domain
    value: basepoint.solidyears.in.net
  - type: domain
    value: baseportion.inherentrecip.ru
  - type: domain
    value: baskadubutil.in.net
ioc_counts:
  domain: 43
  ip: 1
  url: 5
rules:
  - title: Detect Remcos RAT DNS Query
    description: Detects DNS queries to the Remcos RAT domain.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - dns_query
      - windows
  - title: Detect EK_ClearFake Domain Connection
    description: Detects network connections to EK_ClearFake domains.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to EK_ClearFake snoozetrap.in.net Domains
    description: Detects connections to EK_ClearFake domains ending in snoozetrap.in.net.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This brief is based on IOCs identified by Maltrail on February 26, 2026. The IOCs are associated with two distinct threats: Remcos RAT and EK_ClearFake. Remcos RAT is a commercially available remote access trojan often used for malicious purposes, including data theft and surveillance. EK_ClearFake is an exploit kit known for distributing various malware through compromised websites. The domains associated with EK_ClearFake are likely used to host or redirect to landing pages containing exploits. Identifying and blocking these IOCs is crucial to preventing potential infections and mitigating the risk of compromise. This information is relevant for defenders looking to proactively block connections to known malicious infrastructure.

## Attack Chain

The following is a generalized attack chain based on typical Remcos RAT and Exploit Kit (EK_ClearFake) operations.

1.  **Initial Compromise (EK_ClearFake):** User visits a website compromised with EK_ClearFake.
2.  **Redirection (EK_ClearFake):** The compromised website redirects the user to a landing page controlled by the attacker, often using domains like those listed in the IOCs (e.g., `13nq2ksp.lunarbridge.digital`).
3.  **Exploit Delivery (EK_ClearFake):** The landing page probes the user's browser for vulnerabilities.
4.  **Malware Installation (EK_ClearFake):** If a vulnerability is found, the EK_ClearFake delivers and executes a malicious payload.
5.  **Remcos RAT Installation (Remcos):** The delivered payload installs Remcos RAT on the victim's machine.
6.  **Command and Control (Remcos):** Remcos RAT establishes a connection to a command-and-control server (e.g., `oficialrem.duckdns.org`) controlled by the attacker.
7.  **Data Exfiltration (Remcos):** The attacker uses Remcos RAT to steal sensitive data from the compromised system.
8.  **Lateral Movement/Further Exploitation (Remcos):** The attacker leverages the compromised system to move laterally within the network or deploy additional malware.

## Impact

A successful attack involving Remcos RAT can lead to significant data breaches, financial losses, and reputational damage. EK_ClearFake infections can result in widespread malware infections across an organization. The impact could include the theft of sensitive data, disruption of business operations, and the need for extensive incident response efforts. While the number of direct victims from this particular Maltrail feed is unknown, the potential for widespread impact is high given the nature of the tools involved.

## Recommendation

*   Block the listed domains associated with EK_ClearFake (e.g., `13nq2ksp.lunarbridge.digital`) at the DNS resolver level to prevent connections to malicious landing pages.
*   Block the IP address `186.169.75.221` and domain `oficialrem.duckdns.org` associated with Remcos RAT at the firewall to disrupt command and control communications.
*   Deploy the Sigma rules provided below to your SIEM to detect potential Remcos RAT or EK_ClearFake activity within your environment.
*   Investigate systems that communicate with the IOCs identified in this brief to determine the extent of any potential compromise.
