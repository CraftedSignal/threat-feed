---
title: Qilin Ransomware Claims New Victim in French Public Sector
slug: 2026-06-qilin-ransomware-eyguieres
description: The Qilin ransomware group has claimed a new victim, Commune d'Eyguires (www.eyguieres.org), a public sector entity in France, employing their Golang-based ransomware and double extortion tactics, leading to data encryption and potential public release of exfiltrated information.
date: "2026-06-19T14:31:31Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Qilin
  - Agenda
tags:
  - ransomware
  - golang
  - double-extortion
  - public-sector
  - france
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1012
    technique_name: Query Registry
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over Other Network Medium
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.ransomware.live/group/qilin
  - https://www.secureworks.com/research/threat-profiles/gold-feather
  - https://www.trendmicro.com/en_us/research/24/c/agenda-ransomware-propagates-to-vcenters-and-esxi-via-custom-pow.html
  - https://cloud.google.com/blog/topics/threat-intelligence/unc3944-sms-phishing-sim-swapping-ransomware/
  - https://www.trendmicro.com/en_us/research/22/h/new-golang-ransomware-agenda-customizes-attacks.html
iocs:
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
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=28145869-f2d7-4dc2-9171-a26b63fbd83b
ioc_counts:
  hash_md5: 10
  ip: 5
  url: 1
rules:
  - title: Detect Qilin Ransomware Recovery Notes
    description: Detects the creation of Qilin ransomware recovery notes (README files) in common patterns observed for the group, indicating successful encryption.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - file_event
      - windows
  - title: Detect Mimikatz Execution (Qilin Tool)
    description: Detects the execution of Mimikatz, a tool frequently used by Qilin and other ransomware groups for credential access and privilege escalation (OS Credential Dumping).
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003.001
      - T1055
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Outbound FTP Connection (Qilin Exfiltration)
    description: Detects suspicious outbound FTP connections to non-standard destinations, potentially indicating data exfiltration by Qilin ransomware group. This rule specifically targets connections to known Qilin FTP exfiltration IP addresses.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1048
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

The Qilin ransomware group, first observed in July 2022, has claimed Commune d'Eyguires (www.eyguieres.org), a public sector entity in France, as its latest victim. Qilin operates a double extortion model, encrypting victim data and threatening to leak exfiltrated sensitive information if the ransom is not paid. The group's ransomware is written in Golang and allows operators to select multiple encryption modes. Since its emergence, Qilin has victimized at least 1935 organizations globally, with attacks observed since October 2022, demonstrating an average delay of 46.3 days between attack and public claim. This incident highlights the continued threat posed by ransomware groups to critical public services and the importance of robust defenses against data exfiltration and encryption.

## Attack Chain

1.  **Initial Access**: Qilin actors gain initial access to target environments through tactics such as phishing campaigns (e.g., spearphishing via service), exploiting publicly accessible applications (T1190), or compromising valid accounts (T1078).
2.  **Execution & Command and Control (C2)**: Upon gaining access, attackers execute malicious code using built-in command and scripting interpreters (PowerShell, Unix Shell) to establish persistence and set up command and control (C2) channels. Tools like Cobalt Strike or SystemBC are typically used for C2, often communicating over web protocols.
3.  **Defense Evasion & Privilege Escalation**: The group employs various techniques to evade defenses and escalate privileges, including exploiting system vulnerabilities (e.g., Bring-Your-Own-Vulnerable-Driver via Toshiba power management driver), leveraging credential dumping tools such as Mimikatz (T1003.001), and disabling security software or firewalls to reduce detection.
4.  **Lateral Movement & Discovery**: Qilin actors move laterally across the compromised network using remote services (e.g., RDP, SMB, SSH) and tools like NetExec. They perform comprehensive discovery actions to map the network topology, identify valuable systems, and query registry for sensitive information.
5.  **Data Collection & Exfiltration**: Prior to encryption, the group identifies and collects sensitive data from local systems. This data is often archived using native utilities (e.g., `fsutil`) before being exfiltrated to attacker-controlled infrastructure or cloud storage services like EasyUpload.io, MEGA, or FTP servers.
6.  **Impact - Encryption & System Impairment**: The final stage involves deploying the Golang-based ransomware payload to encrypt target data, rendering systems inoperable and files inaccessible (T1486). The threat actors also inhibit system recovery mechanisms and may perform disk wipes (T1490) to ensure data irrecoverability, reinforcing their double extortion strategy.

## Impact

The Qilin ransomware group's attacks result in severe operational disruption and significant financial burdens due to system downtime, recovery costs, and potential ransom payments. Beyond encryption, the double extortion model means sensitive data exfiltrated from victims, such as Commune d'Eyguires in the public sector, is threatened with public release on their leak site. This can lead to severe reputational damage, loss of public trust, and potential regulatory fines due to data breaches, impacting critical services provided by the affected organizations. With 1935 victims globally across sectors like public sector, manufacturing, and healthcare, the financial and operational impact is substantial and widespread.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM/EDR to detect Qilin ransomware activity, specifically focusing on file system events, process creation, and network connections.
*   Block the FTP exfiltration domains `dataShare:2bTWYKNn7aK7Rqp9mnv3@176.113.115.209` and `dataShare:nX4aJxu3rYUMiLjCMtuJYTKS@176.113.115.97` at your network perimeter firewall and proxy servers.
*   Implement strong logging for `process_creation`, `file_event`, and `network_connection` to enable the detection rules and facilitate incident response.
*   Filter network traffic to block connections to the identified malicious IP addresses: `176.113.115.209`, `176.113.115.97`, `188.119.66.189`, `31.41.244.100`, `85.209.11.49`.
*   Regularly patch public-facing applications and systems to prevent exploitation for initial access as described in the attack chain.
