---
title: RMM Domain DNS Queries from Non-Browser Processes
slug: 2024-01-rmm-domain-dns
description: Detects DNS queries to commonly abused remote monitoring and management (RMM) or remote access software domains from non-browser processes, potentially indicating unauthorized remote access or command and control activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - rmm
  - dns
vendors:
  - Elastic
  - Microsoft
  - Mozilla
  - Apple
  - Brave
  - Opera
  - Vivaldi
products:
  - Elastic Defend
  - Sysmon
  - Chrome
  - Edge
  - Firefox
  - Safari
  - Brave Browser
  - Opera Browser
  - Vivaldi Browser
  - WebView2
affected_os:
  - Windows
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
    value: lunixar.com
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
  domain: 75
rules:
  - title: RMM Domain DNS Queries from Non-Browser Processes
    description: Detects DNS queries to commonly abused remote monitoring and management (RMM) or remote access software domains from processes that are not browsers.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - dns_query
      - windows
  - title: RMM Domain DNS Queries - Process Name
    description: Detects DNS queries to RMM domains where the process name is indicative of an RMM tool.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

This detection identifies potentially malicious use of Remote Monitoring and Management (RMM) tools by detecting DNS queries to known RMM domains originating from processes that are not web browsers. Attackers frequently abuse legitimate RMM software for command and control, persistence, and lateral movement within compromised networks. This rule focuses on surfacing RMM clients, scripts, or other non-browser activity contacting these services, thereby increasing the likelihood of detecting unauthorized remote access or malicious activity. The rule aims to reduce false positives by excluding common browser processes and focusing on unusual network activity. The identified domains are associated with various RMM tools like TeamViewer, AnyDesk, and ScreenConnect. This detection is relevant for organizations concerned about insider threats, supply chain attacks, or general compromise leading to unauthorized remote access.

## Attack Chain

1.  An attacker gains initial access to a system, possibly through phishing or exploiting a vulnerability.
2.  The attacker installs an unauthorized RMM tool (e.g., using a script or installer).
3.  The RMM tool initiates a DNS query to resolve its command and control domain (e.g., teamviewer.com).
4.  The system, now running the RMM agent, establishes a connection to the attacker-controlled RMM server.
5.  The attacker uses the RMM tool to execute commands on the compromised system.
6.  The attacker uses the RMM tool for lateral movement within the network.
7.  The attacker uses the RMM tool to maintain persistence on the compromised system.

## Impact

Compromise via unauthorized RMM tools can provide attackers with persistent remote access, enabling them to perform a range of malicious activities, including data theft, ransomware deployment, and further lateral movement within the network. Successful exploitation can lead to significant financial loss, reputational damage, and disruption of business operations. The number of affected systems can vary depending on the scope of the initial compromise and the attacker's ability to move laterally.

## Recommendation

*   Deploy the Sigma rule `RMM Domain DNS Queries from Non-Browser Processes` to your SIEM and tune it to your environment, excluding legitimate non-browser processes that use RMM tools.
*   Investigate any alerts generated by the rule, focusing on identifying the process making the DNS query and its parent process, as outlined in the rule's description.
*   Monitor DNS query logs for queries to the RMM domains listed in the IOC table, and block them at the DNS resolver if unauthorized RMM use is confirmed.
*   Enable Sysmon Event ID 22 (DNS Query) logging to provide the necessary data for this detection, as recommended in the "Setup" section of the content.
