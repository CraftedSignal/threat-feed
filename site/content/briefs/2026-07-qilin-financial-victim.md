---
title: Qilin Ransomware Claims New Financial Services Victim
slug: 2026-07-qilin-financial-victim
description: The Qilin ransomware group, known for its Golang-based ransomware and double extortion tactics, has claimed a new victim in the Financial Services sector, www.tqfinancials.com, as part of its ongoing campaign, highlighting the persistent threat of data encryption and exfiltration.
date: "2026-07-03T19:06:40Z"
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
  - double-extortion
  - financial-services
  - qilin
  - golang
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Exploit Public-Facing Application
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Phishing
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Command and Scripting Interpreter: PowerShell'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Command and Scripting Interpreter: Unix Shell'
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Scheduled Task/Job
    confidence_band: med
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Exploitation for Privilege Escalation
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Obfuscated Files or Information
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: 'Masquerading: Invalid Code Signature'
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: 'Impair Defenses: Disable or Modify System Firewall'
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: 'OS Credential Dumping: LSASS Memory'
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Web Browsers
    evidence: Credentials from Web Browsers
    confidence_band: med
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Query Registry
    confidence_band: med
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: Network Sniffing
    confidence_band: med
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
    evidence: 'Remote Services: Remote Desktop Protocol'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Other Network Medium
    evidence: Exfiltration Over Other Network Medium
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1001
    technique_name: Data Obfuscation
    evidence: Data Obfuscation
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: Proxychains
    confidence_band: med
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
  - type: url
    value: http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=abf9c42a-1ce2-43e2-a6ae-ffe1f669d054
ioc_counts:
  hash_md5: 54
  ip: 5
  url: 1
rules:
  - title: Detect Mimikatz Credential Dumping Activity
    description: Detects common command line arguments used by Mimikatz for credential dumping, often employed by ransomware groups like Qilin for privilege escalation and lateral movement.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Common Cobalt Strike Beacon Processes
    description: Detects suspicious process creation patterns often associated with Cobalt Strike beacons, a tool frequently used by ransomware groups like Qilin for command and control.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1059.001
      - T1059.003
      - T1071.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Qilin ransomware group, first observed in July 2022, has added www.tqfinancials.com, a Financial Services entity, to its list of victims as of July 3, 2026. This group utilizes ransomware written in Golang, supporting multiple encryption modes controlled by the operator. Qilin consistently employs a double extortion model, demanding payment for decryption keys and threatening to release exfiltrated data if demands are not met. The group has claimed a total of 1973 victims, with an average delay of 45.7 days between attack and public claim. The targeting of a financial services organization underscores the group's broad sector targeting and the severe risks of data compromise and business disruption.

## Attack Chain

1.  **Initial Access**: Gaining unauthorized entry, potentially via "Exploit Public-Facing Application" or "Phishing" as listed in Qilin's TTPs.
2.  **Execution & Defense Evasion**: Running malicious code, often using "Command and Scripting Interpreter: PowerShell" and employing "Obfuscated Files or Information" or tools like "EDRSandBlast" to bypass security.
3.  **Credential Access**: Harvesting credentials using tools like "Mimikatz" or leveraging "OS Credential Dumping: LSASS Memory".
4.  **Discovery & Lateral Movement**: Mapping the network with tools such as "Nmap" and moving across systems using "Remote Services" like "PsExec" or "WinRM".
5.  **Collection & Exfiltration**: Gathering sensitive data from various systems and exfiltrating it to attacker-controlled infrastructure, potentially via "EasyUpload.io" or "MEGA" or over FTP using credentials like `dataShare:2bTWYKNn7aK7Rqp9mnv3`.
6.  **Impact**: Deploying the Golang-based ransomware payload to encrypt systems, accompanied by "Data Encrypted for Impact" and "Inhibit System Recovery" actions, including dropping ransom notes like "DtMXQFOCos-RECOVER-README.txt".

## Impact

The impact of a Qilin ransomware attack on a Financial Services organization like www.tqfinancials.com includes severe operational disruption, potential data breaches due to double extortion tactics, and significant financial losses from downtime and recovery efforts. While specific data stolen for this victim is not detailed, Qilin's standard operating procedure involves data exfiltration, posing risks of regulatory fines, reputational damage, and loss of customer trust. The group has a history of impacting a wide range of sectors, with Manufacturing (301 victims), Business Services (262), and Technology (178) among its top targets, indicating its capability to severely compromise diverse organizations.

## Recommendation

*   Deploy the provided IOCs (MD5 hashes, IP addresses, FTP URLs) to your network perimeter defenses (firewall, IDS/IPS, DNS filters) and endpoint detection and response (EDR) solutions to block known Qilin infrastructure.
*   Enable comprehensive logging for process creation, network connections, and PowerShell activity (log source: process_creation) to detect the execution of tools like Mimikatz, Cobalt Strike, Nmap, and PsExec.
*   Implement and enforce strong access controls and multi-factor authentication (MFA) across all critical systems to mitigate credential compromise and lateral movement.
*   Regularly patch and update all public-facing applications and systems to remediate known vulnerabilities that could be leveraged for initial access, as Qilin has been observed to exploit public-facing applications.
*   Deploy robust endpoint detection rules such as "Detect Mimikatz Credential Dumping Activity" and "Detect Common Cobalt Strike Beacon Processes" to identify and block the execution of known Qilin tools and TTPs.
