---
title: DNS Queries to RMM Domains from Non-Browser Processes
slug: 2026-03-rmm-domain-dns
description: Detection of DNS queries to known remote monitoring and management (RMM) domains originating from non-browser processes on Windows systems indicates potential abuse of legitimate software for command and control.
date: "2026-03-24T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - rmm
  - command-and-control
  - windows
references:
  - https://attack.mitre.org/techniques/T1219/002/
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
iocs:
  - type: domain
    value: teamviewer.com
  - type: domain
    value: logmein.com
  - type: domain
    value: logmeinrescue.com
  - type: domain
    value: logmeininc.com
  - type: domain
    value: internapcdn.net
  - type: domain
    value: anydesk.com
  - type: domain
    value: screenconnect.com
  - type: domain
    value: connectwise.com
  - type: domain
    value: splashtop.com
  - type: domain
    value: zohoassist.com
  - type: domain
    value: dwservice.net
  - type: domain
    value: gotoassist.com
  - type: domain
    value: getgo.com
  - type: domain
    value: rustdesk.com
  - type: domain
    value: remoteutilities.com
  - type: domain
    value: atera.com
  - type: domain
    value: ammyy.com
  - type: domain
    value: n-able.com
  - type: domain
    value: kaseya.net
  - type: domain
    value: bomgar.com
  - type: domain
    value: beyondtrustcloud.com
  - type: domain
    value: parsec.app
  - type: domain
    value: parsecusercontent.com
  - type: domain
    value: tailscale.com
  - type: domain
    value: twingate.com
  - type: domain
    value: jumpcloud.com
  - type: domain
    value: vnc.com
  - type: domain
    value: remotepc.com
  - type: domain
    value: netsupportsoftware.com
  - type: domain
    value: getscreen.me
  - type: domain
    value: beanywhere.com
  - type: domain
    value: swi-rc.com
  - type: domain
    value: swi-tc.com
  - type: domain
    value: qetqo.com
  - type: domain
    value: tmate.io
  - type: domain
    value: playanext.com
  - type: domain
    value: supremocontrol.com
  - type: domain
    value: itarian.com
  - type: domain
    value: datto.com
  - type: domain
    value: auvik.com
  - type: domain
    value: syncromsp.com
  - type: domain
    value: pulseway.com
  - type: domain
    value: immy.bot
  - type: domain
    value: immybot.com
  - type: domain
    value: level.io
  - type: domain
    value: ninjarmm.com
  - type: domain
    value: ninjaone.com
  - type: domain
    value: centrastage.net
  - type: domain
    value: datto.net
  - type: domain
    value: liongard.com
  - type: domain
    value: naverisk.com
  - type: domain
    value: panorama9.com
  - type: domain
    value: superops.ai
  - type: domain
    value: superops.com
  - type: domain
    value: tacticalrmm.com
  - type: domain
    value: meshcentral.com
  - type: domain
    value: remotly.com
  - type: domain
    value: fixme.it
  - type: domain
    value: islonline.com
  - type: domain
    value: zoho.eu
  - type: domain
    value: goverlan.com
  - type: domain
    value: iperius.net
  - type: domain
    value: iperiusremote.com
  - type: domain
    value: remotix.com
  - type: domain
    value: mikogo.com
  - type: domain
    value: r-hud.net
  - type: domain
    value: pcvisit.de
  - type: domain
    value: netviewer.com
  - type: domain
    value: helpwire.app
  - type: domain
    value: remotetopc.com
  - type: domain
    value: rport.io
  - type: domain
    value: action1.com
  - type: domain
    value: tiflux.com
  - type: domain
    value: gotoresolve.com
ioc_counts:
  domain: 74
rules:
  - title: DNS Query to Known RMM Domain from Non-Browser Process
    description: Detects DNS queries to known RMM domains from processes excluding common web browsers.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - dns_query
      - windows
  - title: Process Connecting to Known RMM Domain
    description: Detects a non-browser process initiating a network connection to an IP address associated with a known RMM domain.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This brief focuses on the abuse of legitimate Remote Monitoring and Management (RMM) software by threat actors. RMM tools are often used for legitimate IT administration but can be leveraged for malicious purposes such as command and control, persistence, and lateral movement within a compromised network. This activity is identified by detecting DNS queries to a list of known RMM service domains originating from processes that are not typical web browsers. This behavior indicates that an RMM client, script, or other non-browser application is attempting to communicate with an RMM service. The detection rule was published on 2026-03-23 by Elastic and aims to surface unauthorized or malicious use of RMM tools within an organization. It is crucial to differentiate between legitimate and malicious RMM usage by analyzing the context of these DNS queries.

## Attack Chain

1.  An attacker gains initial access to a Windows system through an unknown method.
2.  The attacker installs or deploys a legitimate RMM tool or a modified version.
3.  The RMM agent is configured to communicate with the attacker's command and control infrastructure.
4.  A non-browser process (e.g., a script or a standalone executable) initiates a DNS query to resolve an RMM domain (e.g., teamviewer.com, anydesk.com).
5.  The DNS query is resolved, establishing a network connection between the compromised system and the RMM service or attacker-controlled server.
6.  The attacker leverages the RMM tool to execute commands, transfer files, and maintain persistent access to the compromised system.
7.  The attacker performs lateral movement to other systems within the network, utilizing the RMM tool for remote administration.
8.  The attacker achieves their objective, such as data exfiltration or ransomware deployment, using the established RMM connection.

## Impact

Compromise via RMM tools can lead to significant damage, including unauthorized access to sensitive data, disruption of business operations, and potential ransomware attacks. Successful exploitation allows attackers to maintain persistent access and control over affected systems, facilitating lateral movement and further malicious activities. The widespread use of RMM tools in various sectors makes this a broad threat. The impact can range from a single compromised workstation to the complete takeover of an organization's IT infrastructure.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect DNS queries to RMM domains from non-browser processes and tune for your environment.
*   Review the IOC list of RMM domains and block any unauthorized RMM services at your DNS resolver.
*   Investigate any alerts generated by the Sigma rule by examining the process tree and verifying the legitimacy of the process initiating the DNS query.
*   Implement application control policies to restrict the execution of unauthorized RMM tools on your endpoints.
*   Enable Sysmon DNS event logging to activate the rules above.
