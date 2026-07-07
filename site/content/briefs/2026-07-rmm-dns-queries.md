---
title: Suspicious DNS Queries to Remote Monitoring and Management Domains from Non-Browser Processes
slug: 2026-07-rmm-dns-queries
description: This brief details the detection of DNS queries targeting commonly abused Remote Monitoring and Management (RMM) or remote access software domains, originating from non-browser processes, which is a common tactic for command and control, persistence, and lateral movement by threat actors.
date: "2026-07-06T14:01:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - command-and-control
  - endpoint
  - rmm
  - remote-access
vendors:
  - 01com
  - Action1
  - Addigy
  - AeroAdmin
  - Ammyy
  - AnyDesk
  - Anyplace Control
  - AnySupport
  - Atera
  - Aurelius Host
  - Auvik
  - Aweray
  - Barracuda MSP
  - BeamYourScreen
  - BeAnywhere
  - BeInSync
  - BeyondTrust
  - Bomgar
  - CentraStage
  - Centurion Technologies
  - ConnectWise
  - CrossLoop
  - DameWare
  - Datto
  - Deskday.ai
  - DeskRoll
  - Desktop Streaming
  - Distant Desktop
  - Donkz
  - DWService
  - eHorus
  - Electric AI
  - EMCO Software
  - Ericom
  - FastViewer
  - FixMe.IT
  - FleetDeck
  - GatherPlace
  - GoTo
  - GetScreen
  - Goverlan
  - HeartbeatRM
  - HelpWire
  - HopToDesk
  - Hosted RMM
  - ImmyBot
  - Impero Software
  - Instant Housecall
  - IntelliAdmin
  - Internap CDN
  - Internet ID
  - Iperius Remote
  - ISL Online
  - Itarian
  - ITSupport247
  - JumpCloud
  - Jump Desktop
  - Kabuto
  - Kaseya
  - Kickidler
  - Laplink
  - Level.io
  - Liongard
  - LiteManager
  - LogicNow
  - LogMeIn
  - Lunixar
  - MeshCentral
  - Mikogo
  - Miradore
  - MSP360
  - MyGreenPC
  - N-able
  - Naverisk
  - NCH Software
  - NetOp
  - NetSupport
  - NetViewer
  - NinjaOne
  - NoMachine
  - NTRsupport
  - Opti-Tune
  - Oray
  - Panorama9
  - Parsec
  - PCVisit
  - Pilixo
  - Playanext
  - Pulseway
  - Qetqo
  - R-HUD
  - Real-Time Collaboration
  - Remmon
  - Remote.It
  - Remote Management
  - RemoteCall
  - Remote Desktop
  - RemotePC
  - Remote Utilities
  - Remotix
  - Remotly
  - RepairShopr
  - RMansys
  - RMM Service
  - Royal Apps
  - Rport
  - RUDesktop
  - RustDesk
  - Rview
  - ScreenConnect
  - ScreenMeet
  - Servably
  - Server-Eye
  - Set.Me
  - ShowMyPC
  - SignalServer
  - SimpleHelp
  - Skyfex
  - Sorillus
  - Splashtop
  - SpyAnywhere
  - Spytech-Web
  - StartSupport
  - SuperOps.ai
  - Supremo Control
  - SWI
  - SyncroMSP
  - Syspectr
  - System Monitor
  - Tactical RMM
  - Tailscale
  - TeamViewer
  - Techinline
  - Tele-Desk
  - TiFlux
  - TightVNC
  - tmate
  - ToDesk
  - Twingate
  - UltraViewer
  - UltraVNC
  - VNC
  - Weezo
  - Xeox
  - Zoho
products:
  - 01com
  - Action1
  - Addigy
  - AeroAdmin
  - Ammyy Admin
  - AnyDesk
  - Anyplace Control
  - AnySupport
  - Atera RMM
  - Aurelius Host
  - Auvik
  - Aweray Remote
  - Backdrop Cloud
  - Barracuda MSP
  - BeamYourScreen
  - BeAnywhere
  - BeInSync
  - BeyondTrust Remote Support
  - Bomgar Remote Support
  - CentraStage
  - Centurion Technologies
  - ConnectWise
  - ConnectWise Control (ScreenConnect)
  - CrossLoop
  - DameWare
  - Datto RMM
  - Deskday
  - DeskRoll
  - Desktop Streaming
  - Distant Desktop
  - Donkz
  - DWService
  - eHorus
  - Electric AI RMM
  - EMCO Remote Installer
  - Ericom Connect
  - FastSupport
  - FastViewer
  - FixMe.IT
  - FleetDeck
  - GatherPlace
  - GoToAssist
  - GoToResolve
  - GetScreen
  - Goverlan
  - HeartbeatRM
  - HelpMe.net
  - HelpWire
  - HopToDesk
  - Hosted RMM
  - ImmyBot
  - Impero Remote Monitoring
  - Instant Housecall
  - IntelliAdmin
  - Internap CDN
  - Internet ID
  - Iperius Remote
  - ISL Online
  - Itarian
  - ITSupport247
  - JumpCloud
  - Jump Desktop
  - JumpTo
  - Kabuto
  - Kaseya VSA
  - Kickidler
  - Laplink
  - Level.io
  - Liongard
  - LiteManager
  - LogicNow
  - LogMeIn
  - LogMeIn Rescue
  - Lunixar
  - MeshCentral
  - Mikogo
  - Miradore
  - MSP360
  - MyGreenPC
  - N-able RMM
  - Naverisk
  - NCH Software
  - NetOp Remote Control
  - NetSupport Manager
  - NetViewer
  - NinjaOne
  - NoMachine
  - NTRsupport
  - Opti-Tune
  - Oray Remote Control
  - Panorama9
  - Parsec
  - PCVisit
  - Pilixo
  - Playanext
  - Pulseway
  - Qetqo
  - R-HUD
  - Real-Time Collaboration
  - Remmon
  - Remote.It
  - Remote Management
  - RemoteCall
  - Remote Desktop
  - RemotePC
  - RemoteToPC
  - Remote Utilities
  - Remotix
  - Remotly
  - RepairShopr
  - RMansys
  - RMM Service
  - Royal Apps
  - Rport
  - RUDesktop
  - RustDesk
  - Rview
  - ScreenMeet
  - Servably
  - Server-Eye
  - Set.Me
  - ShowMyPC
  - SignalServer
  - SimpleHelp
  - Skyfex
  - Sorillus
  - Splashtop
  - SpyAnywhere
  - Spytech-Web
  - StartSupport
  - SuperOps.ai
  - Supremo Control
  - SWI Remote Support
  - SyncroMSP
  - Syspectr
  - System Monitor
  - Tactical RMM
  - Tailscale
  - TeamViewer
  - Techinline
  - Tele-Desk
  - TiFlux
  - TightVNC
  - tmate
  - ToDesk
  - Twingate
  - UltraViewer
  - UltraVNC
  - VNC Connect
  - Weezo
  - Xeox
  - Zoho Assist
affected_os:
  - Windows
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_dns_rmm_domains_non_browser.toml
  - https://attack.mitre.org/techniques/T1219/
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
  - https://lolrmm.io/
iocs:
  - type: domain
    value: 01com.com
  - type: domain
    value: 247ithelp.com
  - type: domain
    value: action1.com
  - type: domain
    value: addigy.com
  - type: domain
    value: aeroadmin.com
  - type: domain
    value: ammyy.com
  - type: domain
    value: anydesk.com
  - type: domain
    value: anyplace-control.com
  - type: domain
    value: anysupport.net
  - type: domain
    value: atera.com
  - type: domain
    value: aurelius.host
  - type: domain
    value: auvik.com
  - type: domain
    value: aweray.com
  - type: domain
    value: aweray.net
  - type: domain
    value: backdrop.cloud
  - type: domain
    value: barracudamsp.com
  - type: domain
    value: beamyourscreen.com
  - type: domain
    value: beanywhere.com
  - type: domain
    value: beinsync.com
  - type: domain
    value: beinsync.net
  - type: domain
    value: beyondtrustcloud.com
  - type: domain
    value: bomgar.com
  - type: domain
    value: bomgarcloud.com
  - type: domain
    value: centrastage.net
  - type: domain
    value: centuriontech.com
  - type: domain
    value: connectwise.com
  - type: domain
    value: crossloop.com
  - type: domain
    value: dameware.com
  - type: domain
    value: datto.com
  - type: domain
    value: datto.net
  - type: domain
    value: deskday.ai
  - type: domain
    value: deskroll.com
  - type: domain
    value: desktopstreaming.com
  - type: domain
    value: distantdesktop.com
  - type: domain
    value: donkz.nl
  - type: domain
    value: dwservice.net
  - type: domain
    value: ehorus.com
  - type: domain
    value: electric.ai
  - type: domain
    value: emcosoftware.com
  - type: domain
    value: ericom.com
  - type: domain
    value: fastsupport.com
  - type: domain
    value: fastviewer.com
  - type: domain
    value: fixme.it
  - type: domain
    value: fleetdeck.io
  - type: domain
    value: gatherplace.com
  - type: domain
    value: gatherplace.net
  - type: domain
    value: getgo.com
  - type: domain
    value: getscreen.me
  - type: domain
    value: gotoassist.at
  - type: domain
    value: gotoassist.com
  - type: domain
    value: gotoassist.me
  - type: domain
    value: gotohttp.com
  - type: domain
    value: gotoresolve.com
  - type: domain
    value: goverlan.com
  - type: domain
    value: heartbeatrm.com
  - type: domain
    value: helpme.net
  - type: domain
    value: helpwire.app
  - type: domain
    value: hoptodesk.com
  - type: domain
    value: hostedrmm.com
  - type: domain
    value: immy.bot
  - type: domain
    value: immybot.com
  - type: domain
    value: imperosoftware.com
  - type: domain
    value: instanthousecall.com
  - type: domain
    value: instanthousecall.net
  - type: domain
    value: intelliadmin.com
  - type: domain
    value: internapcdn.net
  - type: domain
    value: internetid.ru
  - type: domain
    value: iperius-rs.com
  - type: domain
    value: iperius.net
  - type: domain
    value: iperiusremote.com
  - type: domain
    value: islonline.com
  - type: domain
    value: islonline.net
  - type: domain
    value: itarian.com
  - type: domain
    value: itsupport247.net
  - type: domain
    value: jumpcloud.com
  - type: domain
    value: jumpdesktop.com
  - type: domain
    value: jumpto.me
  - type: domain
    value: kabuto.io
  - type: domain
    value: kabutoservices.com
  - type: domain
    value: kaseya.com
  - type: domain
    value: kaseya.net
  - type: domain
    value: kickidler.com
  - type: domain
    value: laplink.com
  - type: domain
    value: level.io
  - type: domain
    value: liongard.com
  - type: domain
    value: litemanager.com
  - type: domain
    value: litemanager.ru
  - type: domain
    value: logicnow.com
  - type: domain
    value: logmein-gateway.com
  - type: domain
    value: logmein.com
  - type: domain
    value: logmeininc.com
  - type: domain
    value: logmeinrescue.com
  - type: domain
    value: logmeinrescue.eu
  - type: domain
    value: lunixar.com
  - type: domain
    value: meshcentral.com
  - type: domain
    value: mikogo.com
  - type: domain
    value: mikogo4.com
  - type: domain
    value: miradore.com
  - type: domain
    value: msp360.com
  - type: domain
    value: mygreenpc.com
  - type: domain
    value: n-able.com
  - type: domain
    value: naverisk.com
  - type: domain
    value: nchuser.com
  - type: domain
    value: netop.com
  - type: domain
    value: netsupportmanager.com
  - type: domain
    value: netsupportsoftware.com
  - type: domain
    value: netviewer.com
  - type: domain
    value: ninjaone.com
  - type: domain
    value: ninjarmm.com
  - type: domain
    value: ninjarmm.net
  - type: domain
    value: nomachine.com
  - type: domain
    value: ntrsupport.com
  - type: domain
    value: opti-tune.com
  - type: domain
    value: optitune.us
  - type: domain
    value: oray.com
  - type: domain
    value: oray.net
  - type: domain
    value: panorama9.com
  - type: domain
    value: parsec.app
  - type: domain
    value: parsecusercontent.com
  - type: domain
    value: pcvisit.de
  - type: domain
    value: pilixo.com
  - type: domain
    value: playanext.com
  - type: domain
    value: pulseway.com
  - type: domain
    value: qetqo.com
  - type: domain
    value: r-hud.net
  - type: domain
    value: real-time-collaboration.com
  - type: domain
    value: remmon.hu
  - type: domain
    value: remote.it
  - type: domain
    value: remote.management
  - type: domain
    value: remotecall.com
  - type: domain
    value: remotedesktop.com
  - type: domain
    value: remotepc.com
  - type: domain
    value: remotetopc.com
  - type: domain
    value: remoteutilities.com
  - type: domain
    value: remotix.com
  - type: domain
    value: remotly.com
  - type: domain
    value: repairshopr.com
  - type: domain
    value: rmansys.ru
  - type: domain
    value: rmmservice.ca
  - type: domain
    value: rmmservice.eu
  - type: domain
    value: royalapps.com
  - type: domain
    value: rport.io
  - type: domain
    value: rudesktop.ru
  - type: domain
    value: rustdesk.com
  - type: domain
    value: rview.com
  - type: domain
    value: screenconnect.com
  - type: domain
    value: screenmeet.com
  - type: domain
    value: scrn.mt
  - type: domain
    value: servably.com
  - type: domain
    value: server-eye.de
  - type: domain
    value: set.me
  - type: domain
    value: setme.net
  - type: domain
    value: showmypc.com
  - type: domain
    value: signalserver.xyz
  - type: domain
    value: simple-help.com
  - type: domain
    value: skyfex.com
  - type: domain
    value: sorillus.com
  - type: domain
    value: splashtop.com
  - type: domain
    value: splashtop.eu
  - type: domain
    value: spyanywhere.com
  - type: domain
    value: spytech-web.com
  - type: domain
    value: startsupport.com
  - type: domain
    value: superops.ai
  - type: domain
    value: superops.com
  - type: domain
    value: superopsalpha.com
  - type: domain
    value: superopsbeta.com
  - type: domain
    value: supremocontrol.com
  - type: domain
    value: swi-rc.com
  - type: domain
    value: swi-tc.com
  - type: domain
    value: syncroapi.com
  - type: domain
    value: syncromsp.com
  - type: domain
    value: syspectr.com
  - type: domain
    value: system-monitor.com
  - type: domain
    value: systemmonitor.us
  - type: domain
    value: tacticalrmm.com
  - type: domain
    value: tailscale.com
  - type: domain
    value: teamviewer.com
  - type: domain
    value: techinline.net
  - type: domain
    value: tele-desk.com
  - type: domain
    value: tiflux.com
  - type: domain
    value: tightvnc.com
  - type: domain
    value: tmate.io
  - type: domain
    value: todesk.com
  - type: domain
    value: twingate.com
  - type: domain
    value: ultraviewer.net
  - type: domain
    value: ultravnc.com
  - type: domain
    value: vnc.com
  - type: domain
    value: weezo.me
  - type: domain
    value: weezo.net
  - type: domain
    value: xeox.com
  - type: domain
    value: zoho.eu
  - type: domain
    value: zohoassist.com
  - type: domain
    value: zohoassist.jp
ioc_counts:
  domain: 193
rules:
  - title: Detect DNS Query to Remote Monitoring/Management (RMM) Domain from Non-Browser Process
    description: Detects DNS queries to commonly abused RMM or remote access software domains originating from processes other than common browsers, indicating potential C2 or unauthorized remote access.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - dns_query
      - windows
rules_count: 1
---

This threat brief focuses on the detection of suspicious DNS queries directed towards domains associated with Remote Monitoring and Management (RMM) and remote access software. Threat actors frequently exploit legitimate RMM tools for various malicious purposes, including establishing command and control (C2), maintaining persistence within compromised environments, and facilitating lateral movement. The detection rule specifically targets DNS queries made by non-browser processes, aiming to surface activity from unapproved RMM clients, malicious scripts, or other unexpected software attempting to contact these services. This approach helps defenders identify unauthorized remote access, which could indicate a compromise, or the illicit use of legitimate tools for adversary operations, enabling timely response and mitigation.

## Attack Chain

1.  **Initial Access**: A user falls victim to a phishing email or exploits an internet-facing vulnerability, allowing an attacker to gain an initial foothold on a system.
2.  **Execution & Staging**: Malicious code is executed, often disguised as a legitimate application or utility, which may download further tools or scripts.
3.  **RMM Tool Deployment**: The attacker deploys a legitimate, but often unauthorized or cracked, RMM or remote access client on the compromised system. This could be done through direct installation or by leveraging existing system capabilities.
4.  **Command and Control (C2) Initialization**: The newly deployed RMM client attempts to establish a connection to its control server, which involves performing DNS queries to its service domains (e.g., `teamviewer.com`, `anydesk.com`, `connectwise.com`).
5.  **Persistent Remote Access**: Successful connection to the RMM domain provides the attacker with persistent remote access to the compromised system, often bypassing traditional firewall rules due to the nature of RMM applications.
6.  **Internal Reconnaissance & Lateral Movement**: Using the RMM tool, the attacker conducts internal reconnaissance, maps the network, and moves laterally to other systems within the environment.
7.  **Objective Achievement**: The attacker executes their final objectives, which may include data exfiltration, deployment of ransomware, or further propagation of malware.

## Impact

The abuse of RMM tools by threat actors can lead to severe organizational impact. Successful exploitation can result in unauthorized, persistent access to critical systems, enabling extensive data exfiltration of sensitive information, deployment of ransomware causing significant operational disruption and financial losses, or complete network compromise. Organizations across all sectors, particularly those relying on legitimate RMM for IT support, are susceptible. If the attack succeeds, it can undermine an organization's security posture, lead to regulatory non-compliance, and damage reputation.

## Recommendation

*   Deploy the provided Sigma rule (or its ESQL equivalent) to your SIEM/endpoint security platform and tune for your environment to detect suspicious DNS queries.
*   Ensure that DNS query logging is enabled for all Windows endpoints, ideally via Sysmon Event ID 22 or Elastic Defend, to provide the necessary telemetry for the detection rule.
*   Investigate all alerts generated by the `Detect DNS Query to Remote Monitoring/Management (RMM) Domain from Non-Browser Process` rule, focusing on the `process.executable` and its parent process.
*   Review the code signatures (`process.code_signature`) of flagged processes to verify legitimacy and prevent abuse of trojanized RMM installers.
*   Block the RMM domains listed in the IOC table at the DNS resolver and firewall levels for any systems not explicitly authorized to use such tools.
*   Implement and enforce a strict policy for approved RMM tools and publishers, ensuring only authorized staff use managed, legitimate software for remote support.
