---
title: Astaroth Botnet Deploys New WhatsApp Web Spambot Component
slug: 2026-07-astaroth-spambot-component
description: Operators of the Astaroth (aka Guildma) botnet, which targets Brazil-based users, introduced a new spambot component in Q4 2025 that leverages WhatsApp Web in headless browser mode for malware distribution, exhibiting evasion techniques like payload encryption and WebDriver automation indicator stripping.
date: "2026-07-29T14:53:41Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Astaroth
tags:
  - botnet
  - malware
  - spambot
  - windows
  - latin-america
vendors:
  - Microsoft
  - Google
  - Meta
products:
  - Windows
  - Google Chrome
  - Microsoft Edge
  - WhatsApp Web
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Astaroth is delivered through a downloader script component — often a Windows shortcut (LNK) file running JScript code
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Astaroth is delivered through a downloader script component — often a Windows shortcut (LNK) file running JScript code
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The installer runs an AutoIt-based loader that decodes and executes a Delphi-based loader DLL in memory
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    evidence: The installer runs an AutoIt-based loader that decodes and executes a Delphi-based loader DLL in memory; this DLL subsequently decrypts and executes Astaroth's core component.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: payload encryption, string obfuscation, and in-memory execution
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1622
    technique_name: Debugger Evasion
    evidence: By running a browser instance in headless mode and stripping automation indicators from a WebDriver session, the spambot conducts its entire spam campaign without ever displaying a browser window to the victim.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Astaroth is delivered through a downloader script component — often a Windows shortcut (LNK) file running JScript code — that retrieves an installer component.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: specific language-oriented HTTP headers — confirm Astaroth’s operators are targeting Brazil-based victims.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Data from Information Repositories
    evidence: automatically messaging every contact in each victim’s WhatsApp contact list.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/inside-astaroths-new-spambot-component/
iocs:
  - type: hash_sha256
    value: c7c62303ee1a37fd7a6e2db9c590ba75c647bc4d22d7dca50cfa8879222ac9e1
  - type: hash_sha256
    value: ec43a17685e3a555c2eb5f0a2802e9e45d5a2a5d49a0803155acbd74d9ecdbd7
  - type: hash_sha256
    value: d89105c4d567a95f674ed6eac538e32e288b658a4222a3d52e284a77782af4d5
  - type: domain
    value: stretar7.contabilfacil.sbs
  - type: domain
    value: graconxonjal.empresaeficiente.sbs
  - type: domain
    value: plansonval.impostosrapido.top
  - type: domain
    value: varegjopeaks.com
  - type: domain
    value: docsmoonstudioclayworks.online
ioc_counts:
  domain: 5
  hash_sha256: 3
rules:
  - title: Detect Astaroth Spambot Browser User Data Directory Creation
    description: Detects the creation of temporary directories for browser user data by the Astaroth spambot, which are used to operate WhatsApp Web in headless mode. This is a specific artifact of the spambot component.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1055
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

The Astaroth botnet, also known as Guildma, has evolved its capabilities by integrating a new spambot component since Q4 2025. This component is designed to turn infected victims into unwitting distributors of the malware by automating message delivery via WhatsApp Web. Primarily targeting Brazil-based users, the spambot operates by running a browser instance in headless mode, using WebDriver, and actively stripping automation indicators to avoid detection. The infection chain typically starts with a downloader script, often a malicious Windows shortcut (LNK) file executing JScript, followed by an AutoIt-based loader and a Delphi-based loader DLL that executes Astaroth's core components in memory. This development signifies a significant shift from traditional email-based spam propagation to leveraging trusted social messaging platforms, highlighting the evolving tactics of Latin American eCrime groups.

## Attack Chain

1. Initial access is gained when a victim executes a downloader script component, often a malicious Windows shortcut (LNK) file running JScript code.
2. The JScript code retrieves an installer component from a command and control (C2) server.
3. The installer executes an AutoIt-based loader.
4. The AutoIt loader decodes and executes a Delphi-based loader DLL directly in memory, an evasion technique.
5. The Delphi DLL further decrypts and executes Astaroth's core component, which includes the new spambot functionality.
6. The spambot copies the victim's browser user data to a temporary directory, typically `C:\Users\Public\Temp\ChromeAuto_<BROWSER_ID><DATE>`.
7. It then launches a browser instance, such as Google Chrome or Microsoft Edge, in headless mode, actively stripping WebDriver automation indicators to avoid detection.
8. The spambot accesses WhatsApp Web, collects contact lists from the victim's account, and automatically sends malware distribution messages to all contacts, often utilizing Portuguese-language spam templates.

## Impact

Successful attacks transform victims' systems into unwilling participants in the botnet's distribution efforts, leading to further spread of the Astaroth banking trojan and information stealer. The direct impact on the initial victim includes potential banking fraud, data exfiltration, and compromised system integrity. The new spambot component enables a wider and more credible distribution vector by leveraging trusted social networks, increasing the potential number of infected users, particularly within Brazil. This tactic bypasses traditional email security measures and capitalizes on social trust, making detection and prevention more challenging.

## Recommendation

* Deploy the Sigma rule "Detect Astaroth Spambot Browser User Data Directory Creation" to your SIEM for timely detection of malicious temporary directory creation.
* Block the command and control domains listed in the IOC table at your network perimeter via DNS resolvers or proxy servers.
* Implement the provided YARA rule to scan endpoints and identify the Astaroth spambot component.
* Ensure Sysmon and other endpoint detection and response (EDR) solutions are configured to log `file_event` (specifically `DirectoryCreate` operations) and `process_creation` events to enable rule effectiveness.
