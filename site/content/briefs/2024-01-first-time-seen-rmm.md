---
title: First Time Seen Remote Monitoring and Management Tool Execution
slug: 2024-01-first-time-seen-rmm
description: Detects the execution of previously unseen remote monitoring and management (RMM) tools or remote access software on compromised Windows endpoints, often leveraged for command-and-control, persistence, and execution of malicious commands.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote-access
  - rmm
  - command-and-control
  - persistence
vendors:
  - Elastic
  - Action1 Corporation
  - AeroAdmin LLC
  - Ammyy LLC
  - Atera Networks Ltd
  - AWERAY PTE. LTD.
  - BeamYourScreen GmbH
  - Bomgar Corporation
  - DUC FABULOUS CO.,LTD
  - DOMOTZ INC.
  - DWSNET OÜ
  - FleetDeck Inc
  - GlavSoft LLC
  - Hefei Pingbo Network Technology Co. Ltd
  - IDrive, Inc.
  - IMPERO SOLUTIONS LIMITED
  - Instant Housecall
  - ISL Online Ltd.
  - LogMeIn, Inc.
  - LUNIXAR SAS DE CV
  - MMSOFT Design Ltd.
  - Nanosystems S.r.l.
  - NetSupport Ltd
  - NinjaRMM, LLC
  - Parallels International GmbH
  - philandro Software GmbH
  - Pro Softnet Corporation
  - RealVNC
  - Remote Utilities LLC
  - Rocket Software, Inc.
  - SAFIB
  - Servably, Inc.
  - ShowMyPC INC
  - Splashtop Inc.
  - Superops Inc.
  - TeamViewer
  - Techinline Limited
  - uvnc bvba
  - Yakhnovets Denis Aleksandrovich IP
  - Zhou Huabing
  - ZOHO Corporation Private Limited
  - Connectwise, LLC
  - BreakingSecurity.net
  - Tailscale
  - Twingate
  - RustDesk
  - Zoho
  - JumpCloud
  - ScreenConnect
  - GoTo
products:
  - Elastic Defend
  - Elastic Endgame
  - Sysmon
  - AA_v*.exe
  - AeroAdmin.exe
  - AnyDesk.exe
  - apc_Admin.exe
  - apc_host.exe
  - AteraAgent.exe
  - aweray_remote*.exe
  - AweSun.exe
  - AgentMon.exe
  - B4-Service.exe
  - BASupSrvc.exe
  - bomgar-scc.exe
  - domotzagent.exe
  - domotz-windows-x64-10.exe
  - dwagsvc.exe
  - DWRCC.exe
  - ImperoClientSVC.exe
  - ImperoServerSVC.exe
  - ISLLight.exe
  - ISLLightClient.exe
  - fleetdeck_commander*.exe
  - getscreen.exe
  - g2aservice.exe
  - GoToAssistService.exe
  - gotohttp.exe
  - jumpcloud-agent.exe
  - level.exe
  - LvAgent.exe
  - LMIIgnition.exe
  - LogMeIn.exe
  - Lunixar.exe
  - LunixarRemote.exe
  - LunixarUpdater.exe
  - ManageEngine_Remote_Access_Plus.exe
  - MeshAgent.exe
  - Mikogo-Service.exe
  - NinjaRMMAgent.exe
  - NinjaRMMAgenPatcher.exe
  - ninjarmm-cli.exe
  - parsec.exe
  - PService.exe
  - quickassist.exe
  - r_server.exe
  - radmin.exe
  - radmin3.exe
  - RCClient.exe
  - RCService.exe
  - RemoteDesktopManager.exe
  - RemotePC.exe
  - RemotePCDesktop.exe
  - RemotePCService.exe
  - rfusclient.exe
  - ROMServer.exe
  - ROMViewer.exe
  - RPCSuite.exe
  - rserver3.exe
  - rustdesk.exe
  - rutserv.exe
  - rutview.exe
  - saazapsc.exe
  - ScreenConnect*.exe
  - session_win.exe
  - Remote Support.exe
  - smpcview.exe
  - spclink.exe
  - Splashtop-streamer.exe
  - Syncro.Overmind.Service.exe
  - SyncroLive.Agent.Runner.exe
  - SRService.exe
  - strwinclt.exe
  - Supremo.exe
  - SupremoService.exe
  - tacticalrmm.exe
  - tailscale.exe
  - tailscaled.exe
  - teamviewer.exe
  - ToDesk_Service.exe
  - twingate.exe
  - TiClientCore.exe
  - TSClient.exe
  - tvn.exe
  - tvnserver.exe
  - tvnviewer.exe
  - UltraVNC*.exe
  - UltraViewer*.exe
  - vncserver.exe
  - vncviewer.exe
  - winvnc.exe
  - winwvc.exe
  - Zaservice.exe
  - ZohoURS.exe
  - Velociraptor.exe
  - ToolsIQ.exe
  - CagService.exe
  - ScreenConnect.ClientService.exe
  - TiAgent.exe
  - GoToResolveProcessChecker.exe
  - GoToResolveUnattended.exe
  - Syncro.Installer.exe
affected_os:
  - windows
references:
  - https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
  - https://attack.mitre.org/techniques/T1219/002/
  - https://github.com/redcanaryco/surveyor/blob/master/definitions/remote-admin.json
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
  - https://www.cisa.gov/sites/default/files/2025-06/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf
rules:
  - title: Detect RMM Tools Execution via Process Name
    description: Detects the execution of known RMM tools based on process name.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - process_creation
      - windows
  - title: Detect RMM Tools Execution via Code Signature
    description: Detects the execution of known RMM tools based on the code signature subject name.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - process_creation
      - windows
  - title: Detect RMM Tools Execution via CommandLine
    description: Detects the execution of known RMM tools based on process CommandLine.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers commonly abuse legitimate remote monitoring and management (RMM) tools and remote access software for command and control (C2), persistence, and execution of native commands on compromised endpoints. These tools provide attackers with the ability to maintain access, execute commands, and move laterally within a network. This detection identifies when a process associated with commonly abused RMM/remote access tools is observed for the first time on a host. The rule is designed to trigger when a new process name or code signature associated with RMM software, or a child process of such software, is seen within a configured history window. This helps defenders quickly identify potentially malicious use of legitimate tools.

## Attack Chain

1.  Initial Access: The attacker gains initial access to a target system through various methods, such as exploiting vulnerabilities or using compromised credentials.
2.  Tool Deployment: The attacker deploys a remote monitoring and management (RMM) tool or remote access software on the compromised endpoint. This may involve downloading and installing the tool, or exploiting existing installations.
3.  Persistence: The RMM tool is configured to run persistently on the system, ensuring that the attacker maintains access even after a reboot or other disruption. This may involve creating a service or adding a registry key to ensure the tool starts automatically.
4.  Command and Control: The attacker uses the RMM tool to establish a command and control (C2) channel with the compromised system. This allows them to remotely execute commands, transfer files, and monitor activity on the system.
5.  Lateral Movement: Using the RMM tool, the attacker moves laterally within the network, compromising additional systems and escalating their access. This may involve using the tool to access shared resources or execute commands on other systems.
6.  Data Exfiltration or Ransomware Deployment: The attacker uses their access to exfiltrate sensitive data from the compromised network or deploy ransomware to encrypt files and demand a ransom payment.
7.  Cleanup: The attacker may attempt to remove traces of their activity, such as logs or files associated with the RMM tool, to avoid detection.

## Impact

Compromise via RMM tools can lead to significant data breaches, financial losses, and reputational damage. The use of legitimate tools makes detection more difficult. Successful attacks can result in ransomware deployment, data theft, and prolonged unauthorized access to sensitive systems. Organizations in all sectors are potentially at risk.

## Recommendation

*   Deploy the process creation rule to detect the execution of RMM tools on endpoints based on `process.name` and `process.code_signature.subject_name` criteria in the query.
*   Enable Sysmon process creation logging (Event ID 1) to ensure the collection of necessary event data for the detection rule.
*   Investigate any alerts generated by the detection rule to determine whether the execution of the RMM tool is authorized and legitimate. Refer to the references for a list of commonly abused RMM tools and associated indicators.
