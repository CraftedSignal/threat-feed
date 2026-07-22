---
title: TrickBot Variant Utilizes DNS Tunneling for Command and Control
slug: 2026-07-trickbot-dns-tunneling
description: FortiGuard Labs analyzed a new TrickBot variant that employs DNS tunneling for command and control communications, modular execution, and incorporates persistence and obfuscation techniques to evade detection and maintain presence on infected systems.
date: "2026-07-22T13:05:30Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TrickBot
tags:
  - malware
  - banking-trojan
  - dns-tunneling
  - c2
  - persistence
  - obfuscation
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: a TrickBot variant that uses DNS tunneling for C2 communication
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: employs persistence
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: employs ... obfuscation techniques
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: modular execution
    confidence_band: med
references:
  - https://feeds.fortinet.com/~/961655441/0/fortinet/blog/threat-research~Inside-a-TrickBot-Variant-Using-DNS-Tunneling-for-C
---

FortiGuard Labs has identified and analyzed a new variant of the TrickBot banking trojan, a notorious and highly modular malware historically associated with financial fraud and used as a precursor for ransomware deployments. This variant distinguishes itself by leveraging DNS tunneling for its command and control (C2) communications, a technique that allows data to be exfiltrated or commands to be received over DNS queries and responses, often bypassing traditional firewall and proxy controls. Beyond its novel C2 mechanism, the variant maintains TrickBot's characteristic modular execution, enabling it to download and run various payloads dynamically. It also integrates sophisticated persistence mechanisms to ensure long-term presence on compromised systems and employs obfuscation techniques to hinder analysis and detection by security solutions. This development highlights the ongoing evolution of TrickBot's capabilities, posing a significant threat to organizations due to its stealthy C2 and potential for multifaceted attacks.

## Impact

The successful compromise by this TrickBot variant can lead to severe consequences for organizations. TrickBot is well-known for its capabilities in credential harvesting, exfiltrating sensitive financial and personal data, and acting as a primary loader for other potent malware families, including various ransomware strains. If this variant successfully establishes persistence and C2, it could result in substantial financial losses through banking fraud, intellectual property theft, data breaches, and significant operational disruption if ransomware is subsequently deployed. Its use of DNS tunneling makes detection challenging, increasing the likelihood of a prolonged dwell time and more extensive damage before the threat is identified and contained.

## Recommendation

* Configure DNS servers and network monitoring solutions to log all DNS queries and responses, specifically looking for abnormally long query names, unusual query types, or frequent queries to non-existent domains, which may indicate DNS tunneling activity.
* Implement network segmentation to limit the lateral movement capabilities of malware should an infection occur, thereby reducing the scope of potential DNS tunneling egress.
* Deploy endpoint detection and response (EDR) solutions capable of detecting abnormal process behavior, attempts at modifying common persistence locations (e.g., Run keys), and dynamic code execution, which can signal modular execution.
* Regularly review and audit security event logs from firewalls and DNS infrastructure for suspicious outbound DNS traffic patterns or high volumes of DNS queries from internal hosts to external authoritative name servers that are not part of legitimate operations.
