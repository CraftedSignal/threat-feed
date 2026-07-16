---
title: HelloNet Campaign Uses ViPNet Update System for Malicious Module Delivery
slug: 2026-07-hellonet-vipnet
description: An unknown sophisticated threat actor is leveraging DLL sideloading within the ViPNet update system to deploy a multi-stage malware suite, including HelloInjector, HelloProxy, HelloExecutor, HelloCleaner, and HelloBackdoor, to establish persistence, exfiltrate data, and maintain covert access to large Russian organizations in government, energy, and other critical sectors.
date: "2026-07-16T14:52:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - apt
  - dll-sideloading
  - persistence
  - proxy
  - c2
  - reconnaissance
  - data-exfiltration
  - russia
  - windows
vendors:
  - InfoTeCS
products:
  - ViPNet Update System
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: By placing the file in this directory, the attackers implement the DLL Sideloading technique — the ViPNet update system executable file itcsrvup64.exe, which is launched at OS startup, is susceptible to it. Thus, during this attack, the attackers tried to implement persistence on the system through the ViPNet software update component.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    evidence: Its main goal is to inject its code into the svchost.exe process and launch the malicious payload. ... the loader injects itself into the target process using the NtWriteVirtualMemory and NtCreateThreadEx functions.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: 'The attackers launched a renamed executable file of the legitimate PuTTY utility (a client for various remote access protocols): C:\users\public\music\frontpage.exe'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
    evidence: A module for cleaning ViPNet software log files, which we named HelloCleaner. It allows hiding the attackers&#8217; actions in the system.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: 'The malicious payload, which we named HelloProxy, is simultaneously a hidden proxy... The malware accepts strings in the following format: <ip_addr>:<port> Afterwards, it creates new sockets and starts forwarding traffic between them.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: the attackers used this directory when launching an SSH tunnel from the infected infrastructure to the attackers&#8217; command server (5.39.253[.]206).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'The HelloExecutor backdoor was used for reconnaissance in the networks of infected organizations. The following shell commands were executed: query user, ipconfig /all, net user /do, net group /do, dir'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: 'The following shell commands were executed: query user, net user /do'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Configuration Discovery
    evidence: 'The following shell commands were executed: ipconfig /all'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: 'The following shell commands were executed: dir ''C:\Program Files (x86)'', dir ''C:\Program Files (x86)\infotecs\'', dir ''C:\Program Files (x86)\infotecs\ViPNet Administrator'', dir ''C:\Program Files (x86)\infotecs\ViPNet Client\Export'', dir ''C:\Program Files (x86)\infotecs\ViPNet Client'', dir ''С:\ProgramData\Infotecs\ViPNet Administrator\kc\Export\'', dir ''$appdata\Infotecs\ViPNet Administrator\kc\Export\ Dst for network <номер сети удален>'', dir c:\users\[username], dir C:\Users\Public\music'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: the attackers used this directory when launching an SSH tunnel from the infected infrastructure to the attackers&#8217; command server (5.39.253[.]206).
    confidence_band: high
references:
  - https://securelist.com/tr/hellonet-vipnet/120700/
iocs:
  - type: ip
    value: 5.39.253.206
ioc_counts:
  ip: 1
rules:
  - title: Detect HelloNet Campaign - ViPNet DLL Sideloading (HelloInjector)
    description: Detects the creation of the malicious wtsapi32.dll (HelloInjector) in the ViPNet Update System directory, used for DLL sideloading.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - windows
  - title: Detect HelloNet Campaign - HelloProxy Log File Creation
    description: Detects the creation of the tesh4RPC.txt log file by the HelloProxy module, indicating active C2 communication logging.
    platform: sigma
    severity: high
    tactics:
      - collection
      - impact
    data_sources:
      - file_event
      - windows
  - title: Detect HelloNet Campaign - Renamed PuTTY Execution for SSH Tunnel
    description: Detects the execution of a renamed PuTTY client (frontpage.exe) from the Public Music directory, used by HelloNet for SSH tunneling to the C2 server.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1036.003
      - T1572
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Since at least May 2026, a sophisticated and currently unattributed threat actor has been conducting the "HelloNet" campaign, targeting large Russian organizations across government, energy, transport, education, logistics, and industry sectors. The campaign is notable for its innovative use of the legitimate ViPNet update system, a software suite designed for secure network communication. Attackers exploit a DLL sideloading vulnerability within the ViPNet update component, `itcsrvup64.exe`, to load a malicious module named HelloInjector. This initial implant then facilitates the deployment of a sophisticated malware ecosystem, including HelloProxy for covert communication and proxying, HelloExecutor for reconnaissance, HelloCleaner for log evasion, and a Rust-based HelloBackdoor for file manipulation and persistent access. This campaign represents a significant threat due to its stealth, persistence mechanism, and targeting of critical infrastructure.

## Attack Chain

1. **DLL Sideloading**: The attackers place a malicious `wtsapi32.dll` file (dubbed HelloInjector) into the `C:\Program Files (x86)\InfoTeCS\VIPNet Update System` directory, exploiting a legitimate ViPNet software component.
2. **Persistence & Injection**: The legitimate ViPNet update service executable, `itcsrvup64.exe`, loads the malicious `wtsapi32.dll` at operating system startup. HelloInjector then injects its code into an `svchost.exe` process (specifically one with `netsvcs` in its command line) using `NtWriteVirtualMemory` and `NtCreateThreadEx`.
3. **Loader Execution**: Once injected, HelloInjector loads and executes the primary payload, HelloProxy, directly from its body into the memory of the `svchost.exe` process.
4. **Covert C2 & Proxying**: HelloProxy establishes covert command and control (C2) communication by listening on ports 5003 and 5060. It intercepts `NtDeviceIoControlFile`, `closesocket`, and `shutdown` functions to evade security solutions, performs a specific handshake (0x0502 followed by `ASDFASFSAFASDF`), and acts as a hidden proxy and loader for subsequent malicious modules. It also logs incoming messages to `C:\users\public\tesh4RPC.txt`.
5. **Module Deployment & Reconnaissance**: HelloProxy loads additional modules from the C2 server, including HelloExecutor, which executes reconnaissance commands such as `query user`, `ipconfig /all`, `net user /do`, and various `dir` commands to map the compromised network. Another module, HelloCleaner, is deployed to delete ViPNet software log files, covering the attackers' tracks.
6. **Data Exfiltration & Remote Access**: The attackers deploy a renamed legitimate PuTTY executable, `frontpage.exe`, in `C:\Users\Public\Music`. This tool is used to establish an SSH tunnel to the C2 server `5.39.253[.]206` for data exfiltration and maintaining remote access. Additionally, a Rust-based HelloBackdoor is deployed, listening on port 443 for additional file system manipulation and command execution.

## Impact

The HelloNet campaign primarily targets large Russian organizations across multiple critical sectors including government, energy, transport, education, logistics, and industry. Successful compromise results in persistent unauthorized access to victims' networks, enabling extensive reconnaissance, data exfiltration, and potential disruption of operations. The use of legitimate system components and sophisticated evasion techniques makes detection challenging, increasing the risk of prolonged dwell time and significant financial and operational damage to affected entities. The campaign has been active since at least May 2026.

## Recommendation

* Enable Sysmon file creation and process creation logging to activate the rules above.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious DLL sideloading and execution of renamed utilities.
* Block the C2 IP `5.39.253[.]206` at the network perimeter.
* Monitor file creation events for `C:\Program Files (x86)\InfoTeCS\VIPNet Update System\wtsapi32.dll` to detect HelloInjector deployment.
* Monitor `svchost.exe` process memory for unusual injection activity using memory forensics tools.
* Monitor for file creation at `C:\users\public\tesh4RPC.txt` which indicates HelloProxy logging activity.
* Regularly review process creation logs for unusual executables, such as `frontpage.exe` in `C:\Users\Public\Music`, and command-line arguments indicative of SSH tunneling.
* Conduct network traffic monitoring for outbound connections to `5.39.253[.]206` on any port, and for unusual traffic on ports 5003, 5060, and 443.
