---
title: Daemon Tools Supply Chain Attack Targeting Government and Scientific Entities
slug: 2026-05-daemon-tools-supply-chain
description: A supply chain attack involving trojanized Daemon Tools versions 12.5.0.2421 to 12.5.0.2434 delivered a sophisticated backdoor to a limited number of government, scientific, manufacturing, and retail organizations after a broader initial infection.
date: "2026-05-06T08:34:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - backdoor
  - daemon tools
vendors:
  - AVB Disc Soft
products:
  - Daemon Tools (12.5.0.2421 to 12.5.0.2434)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.securityweek.com/government-scientific-entities-hit-via-daemon-tools-supply-chain-attack/
iocs:
  - type: domain
    value: DiscSoftBusServiceLite.exe
  - type: domain
    value: DTShellHlp.exe
  - type: domain
    value: DTHelper.exe
ioc_counts:
  domain: 3
rules:
  - title: Detect Daemon Tools Compromised Binaries
    description: Detects the execution of known compromised Daemon Tools binaries
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Execution from Daemon Tools binaries
    description: Detects execution of suspicious processes with a parent process being a Daemon Tools Binary
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

In May 2026, Kaspersky reported a supply chain attack targeting government, scientific, manufacturing, and retail organizations through compromised versions of Daemon Tools disk imaging software. Attackers injected malicious code into Daemon Tools versions 12.5.0.2421 to 12.5.0.2434, which were available for download from the legitimate website starting April 8, 2026. Three binaries within the software—DTHelper.exe, DiscSoftBusServiceLite.exe, and DTShellHlp.exe—were compromised with injected code and signed with valid AVB Disc Soft certificates. This resulted in a widespread initial infection attempting to deploy an information collector across over 100 countries. After the initial infection, the attackers deployed a second, minimalistic backdoor on a dozen systems of interest in Belarus, Russia, and Thailand, and the QUIC RAT on a single educational institution in Russia.

## Attack Chain

1.  Attackers inject malicious code into legitimate Daemon Tools binaries (DTHelper.exe, DiscSoftBusServiceLite.exe, and DTShellHlp.exe).
2.  Compromised Daemon Tools versions 12.5.0.2421 to 12.5.0.2434 are made available for download via the legitimate website.
3.  Users download and install the trojanized Daemon Tools software.
4.  When one of the compromised binaries is launched (at machine startup), the injected backdoor is activated.
5.  The backdoor sends requests to a typosquatting domain.
6.  The server responds with a shell command executed via command prompt to fetch and run a payload.
7.  The attackers deploy an information collector on thousands of machines across over 100 countries.
8.  Based on collected information, the attackers deploy a second, minimalistic backdoor on select systems and the QUIC RAT on others for further exploitation and data collection.

## Impact

The supply chain attack compromised government, scientific, manufacturing, and retail organizations. While thousands of machines were initially infected to deploy an information collector, a second backdoor was specifically deployed to a dozen systems in Belarus, Russia, and Thailand. The QUIC RAT was deployed against an educational institution in Russia. The intent of the attackers is unclear, but the targeted nature of the second-stage infections suggests cyberespionage or "big game hunting."

## Recommendation

*   Monitor process executions for the compromised Daemon Tools binaries (DTHelper.exe, DiscSoftBusServiceLite.exe, and DTShellHlp.exe) using process_creation logs.
*   Implement network monitoring to detect connections to known typosquatting domains associated with the attack.
*   Deploy the Sigma rules provided below to detect malicious command line activity and modified Daemon Tools binaries.
