---
title: 'The TTF Trap: Global Phishing Campaign Leverages Obfuscated JScript and Lua Loaders for RATs and Infostealers'
slug: 2026-07-ttf-trap-lua-loader-campaign
description: FortiGuard Labs identified a global phishing campaign employing obfuscated JScript, disguised TrueType Font (.ttf) files, and Lua loaders to deliver remote access Trojans (RATs) and infostealers to victims.
date: "2026-07-16T13:32:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - loader
  - jscript
  - lua
  - rat
  - infostealer
  - malware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: FortiGuard Labs analyzes a global phishing campaign using obfuscated JScript, disguised .ttf files, and Lua loaders to deliver RATs and infostealers.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: obfuscated JScript
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: obfuscated JScript
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: obfuscated JScript, disguised .ttf files
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
    evidence: low-detection Lua Loader
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: deliver RATs and infostealers.
    confidence_band: med
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: deliver RATs and infostealers.
    confidence_band: med
references:
  - https://feeds.fortinet.com/~/960560447/0/fortinet/blog/threat-research~The-TTF-Trap-A-Global-Campaign-of-a-LowDetection-Lua-Loader
---

FortiGuard Labs has uncovered a widespread phishing campaign, dubbed "The TTF Trap," that is actively deploying sophisticated malware, including Remote Access Trojans (RATs) and infostealers, by leveraging highly obfuscated JScript and custom Lua loaders. This global campaign utilizes deceptive tactics, often disguising malicious payloads as legitimate TrueType Font (.ttf) files, to evade detection. The threat actors behind this operation employ multiple layers of obfuscation and a low-detection Lua-based loading mechanism to ensure their malicious tools persist on compromised systems. The campaign, ongoing since at least July 2026, poses a significant risk to organizations worldwide, as successful compromises can lead to extensive data exfiltration, unauthorized system access, and further malicious activities without immediate detection.

## Attack Chain

1. Phishing emails or messages are sent to targets, containing malicious attachments or links to download files.
2. Victims download and execute what appears to be a legitimate file, often disguised as a TrueType Font (.ttf) file.
3. The disguised file, which is actually an executable or script, deploys an initial obfuscated JScript payload.
4. The JScript then executes a Lua loader, which is designed with low detection rates to bypass security mechanisms.
5. The Lua loader establishes communication with attacker-controlled infrastructure to download additional malicious components.
6. Final payloads, including Remote Access Trojans (RATs) and infostealers, are downloaded and executed on the compromised system.
7. The RATs enable full remote control, while infostealers exfiltrate sensitive data such as credentials, financial information, and personal files.

## Impact

Successful attacks from this global phishing campaign result in severe consequences for targeted organizations and individuals. Victims may experience unauthorized remote access to their systems via RATs, leading to complete system compromise, intellectual property theft, and potential lateral movement across networks. Infostealers deployed in this campaign are designed to exfiltrate sensitive data, including login credentials, banking details, and other confidential information, which can be used for financial fraud, identity theft, or sold on dark web marketplaces. The low-detection nature of the Lua loader also means that compromises can remain undetected for extended periods, maximizing the damage and enabling prolonged espionage or data theft.

## Recommendation

* Enable comprehensive logging for script execution, especially for JScript and VBScript, on all endpoints to provide visibility into potential malicious activity.
* Deploy endpoint detection and response (EDR) solutions capable of behavioral analysis to identify suspicious process chains involving script interpreters (e.g., `wscript.exe`, `cscript.exe`) launching unusual child processes or making network connections.
* Educate users on identifying and reporting phishing attempts, particularly those involving unexpected font files or script attachments, as initial access relies on user interaction.
* Implement email gateway filters to block emails containing suspicious attachments, especially executable files disguised with common extensions like .ttf or .pdf, to prevent initial access.
* Monitor network traffic for unusual outbound connections from internal hosts to identify potential Command and Control (C2) communications by RATs and infostealers.
