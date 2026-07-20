---
title: 'Unpacking ''Cruciferra'': Analysis of a Sophisticated Crypter Service'
slug: 2026-07-cruciferra-crypter-service
description: Cruciferra is a sophisticated crypter-as-a-service, written in Mono, actively developed and sold to multiple cybercriminal threat actors who use it to deliver a wide range of remote access trojans and infostealers, employing extensive defense evasion techniques like BYOVD-based EDR tampering, Process Ghosting, and unique cryptographic obfuscation via email-based phishing campaigns.
date: "2026-07-20T09:04:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - crypter
  - malware-as-a-service
  - defense-evasion
  - remote-access-trojan
  - infostealer
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: In observed campaigns, malware is delivered via email, with Cruciferra used to obfuscate the ultimate payload... The URLs leading to these landing pages were delivered either directly within the email body or via PDF attachments cotaining embedded links.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: the actor leveraged tax-themed lures to drive victims to attacker-controlled landing pages hosting ZIP files containing an executable and DLL pair... These messages contained URLs leading to the download of a VHD file which, if clicked, ran an executable...
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: messages contained URLs masquerading as links to evidence provided by a guest, but led to the download of a zipped LNK file that launched a PowerShell command, which then executed a PowerShell script.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Cruciferra is always executed via DLL side-loading. The infection chain involves a ZIP or similar archive file that contains an executable and a DLL. When the target runs the executable file, the DLL (which contains Cruciferra’s code) is side-loaded, and the executable invokes the main malicious function code inside the DLL.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The malware employs extensive defense-evasion capabilities and over 90 variations of cryptographic functions to obfuscate its data and payloads... Cruciferra supports a large collection of custom encryption routines, many of which appear to be dynamically assembled from components of established cryptographic algorithms.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: BYOVD-based EDR tampering
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    evidence: a customized implementation of Process Ghosting used to execute payloads while minimizing forensic artifacts.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: This script first fingerprinted the user's system and reported the collected information to an actor-controlled server.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: BYOVD-based EDR tampering, privilege escalation
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Cruciferra has the option of either dropping the payload to disk or downloading a payload from a staging server.
    confidence_band: high
references:
  - https://www.proofpoint.com/us/blog/threat-insight/unpacking-cruciferra-analysis-sophisticated-crypter-service
iocs:
  - type: domain
    value: exploit.in
  - type: hash_sha256
    value: 17aae57cf6255c7eb169bf62ea67376d9708976eb7831f8cdd0ea38bdcb37dc4
  - type: hash_sha256
    value: 2fdfdd13a0c548bb68c9d5aa8599a9265d4659da3e237fe7a42ac6ac06b9a06a
  - type: hash_sha256
    value: c4e93449453cf67c5d5605bb8f425207a738a242fdb432d720acc32faa74926c
  - type: hash_sha256
    value: c5b1e9aafc8f2b4ab05effc00fd43f3114b9ef1d592a086c952793ac4e299809
  - type: hash_sha256
    value: 7887e919555fb5948c217556ba149392a72982b1bc427d3db779db9dcbf09ee8
  - type: hash_sha256
    value: 09bedbf7a41e0f8dabe4f41d331db58373ce15b2e9204540873a1884f38bdde1
  - type: hash_sha256
    value: 5b4f59236a9b950bcd5191b35d19125f60cfb9e1a1e1aa2e4f914b6745dde9df
  - type: hash_sha256
    value: c46e907886e2158cbc453e767183aecf07887b5ac8848f19684451883d69f5f0
  - type: hash_sha256
    value: 3c181f642e24c28602a87be7f195e2f3d1ffa30b37e20f5121d99f88b22ab80e
  - type: hash_sha256
    value: 66dbe675480dc229e5b3ab8ad74207f73486e64e57805074f784bb2e01bcb865
ioc_counts:
  domain: 1
  hash_sha256: 10
rules:
  - title: Detect Loading of Known Vulnerable Drivers Used by Cruciferra
    description: Detects the loading of specific vulnerable drivers identified in Cruciferra campaigns for BYOVD-based EDR tampering. These drivers are known to be abused by threat actors to gain elevated privileges and evade security solutions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
      - T1562.002
    data_sources:
      - image_load
      - windows
rules_count: 1
---

Proofpoint researchers are tracking "Cruciferra", a sophisticated crypter-as-a-service employed by various cybercriminal threat clusters to obfuscate and deliver a wide range of remote access trojans (RATs) and infostealers. First made available for sale in the fall of 2025 on underground forums like Exploit[.]in, Cruciferra is actively developed, with testing variants observed. Written in Mono, it incorporates numerous evasion techniques, including indirect system calls, API and IAT unhooking, Bring-Your-Own-Vulnerable-Driver (BYOVD)-based EDR tampering, privilege escalation, and a customized implementation of Process Ghosting. Its notable emphasis on payload protection involves over 90 variations of cryptographic functions, dynamically assembled, to complicate static analysis and signature-based defenses. The service is typically used in email phishing campaigns with opportunistic targeting, though financial services, healthcare, and government entities have been frequently observed as victims, delivering malware such as zgRAT, AsyncRAT, XWorm, and AgentTesla.

## Attack Chain

1. Threat actors send email phishing messages with tax-themed or guest complaint lures to victims. These emails contain either direct links or PDF attachments with embedded malicious links.
2. Victims click the malicious links, leading to attacker-controlled landing pages that host compressed archives (ZIP or VHD files) containing malicious files like an executable and a DLL, or a malicious LNK file.
3. The user executes the downloaded file, which triggers DLL side-loading of Cruciferra's malicious DLL, launching the crypter's code.
4. Cruciferra executes, performing anti-analysis and defense evasion checks to detect sandboxes, virtual machines, and analysts by using numerous decoy exported functions and techniques to hide console windows.
5. A PowerShell script or an internal Cruciferra module collects system information, performing system fingerprinting (e.g., CPU, memory, OS, network adapters, running processes, drives, services).
6. Cruciferra performs Bring-Your-Own-Vulnerable-Driver (BYOVD) attacks, loading known vulnerable drivers (e.g., `GoFlyDrv.sys`, `MemoryInformer.sys`) to unhook APIs or tamper with EDRs, and also utilizes Process Ghosting to execute payloads covertly.
7. Cruciferra either drops the obfuscated final payload (e.g., AsyncRAT, XWorm, zgRAT, AgentTesla) to disk or downloads it from a staging server and executes it.
8. The final payload establishes remote access, exfiltrates sensitive information, or performs other malicious activities as per the specific malware delivered (e.g., remote access, information theft).

## Impact

Cruciferra's use by multiple threat actors in opportunistic phishing campaigns has led to widespread compromises, with observed targeting across various sectors including financial services, healthcare, and government entities. The successful deployment of Cruciferra results in the installation of commodity malware like zgRAT, AgentTesla, AsyncRAT, XLoader, XWorm, Phantom Stealer, Formbook, and Remcos. Consequences for victims include remote system control, data exfiltration, and potential further exploitation or financial fraud. The crypter's sophisticated evasion techniques make detection and analysis difficult, increasing the likelihood of successful infections and prolonged dwell times for the delivered payloads.

## Recommendation

* Deploy the Sigma rule "Detect Loading of Known Vulnerable Drivers Used by Cruciferra" to your SIEM to identify BYOVD attempts leveraging specific vulnerable drivers.
* Block the C2 domains and URLs listed in the IOC table (e.g., `hxxp://hsahyteiows[.]gu[.]cc`, `hxxp://fuaytrwese[.]love`) at the DNS resolver or proxy level.
* Implement email filtering and security awareness training to help users identify and report phishing attempts, especially those using tax or guest complaint lures, which are common initial access vectors for Cruciferra campaigns.
* Ensure endpoint detection and response (EDR) solutions are configured to monitor for suspicious process creation, DLL loading, and driver installations, which are indicative of Cruciferra's evasion techniques like DLL side-loading and BYOVD.
* Configure network security tools to monitor for outbound connections to the identified payload delivery URLs and C2 infrastructure.
