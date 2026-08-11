---
title: Aeternum Botnet Leverages Polygon Blockchain for Decentralized C2
slug: 2026-08-aeternum-botnet
description: Aeternum is a C++ botnet loader that utilizes Polygon blockchain smart contracts for resilient, decentralized command-and-control communication and payload delivery.
date: "2026-08-11T01:24:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - botnet
  - blockchain
  - C2
  - malware
  - execution
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: Creates a Windows shortcut under the program menu's Startup directory (Wmi_Framework_APIKEY_wmsnet_<random_value>.lnk) to ensure auto-launch upon reboot.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1568.002
    technique_name: 'Dynamic Resolution: Domain Generation Algorithms'
    evidence: The Aeternum botnet uses decentralized networks and evasion techniques, such as virtual machine detection and antivirus scanning, to operate effectively.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
    evidence: Sends JSON-RPC requests to Polygon RPC endpoints (decentralized C2 communication).
    confidence_band: high
iocs:
  - type: hash_sha256
    value: 5bfb25b8255b61e5ffdf6804451534bcfa9f1dfd225e6c8cdcefb5f50d846898
  - type: domain
    value: polygon-mumbai-bor-rpc.publicnode.com
  - type: url
    value: https://api.telegram.org
ioc_counts:
  domain: 1
  hash_sha256: 1
  url: 1
rules:
  - title: Detect Aeternum Botnet Persistence via Startup Shortcut
    description: Detects the creation of malicious Windows shortcut files in the Startup directory associated with Aeternum botnet persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Aeternum is a sophisticated C++-based botnet loader that decentralizes its command-and-control (C2) operations by hosting instructions directly on the Polygon blockchain. By leveraging smart contracts, the threat actors eliminate the need for traditional, takedown-prone infrastructure. The malware, often masquerading as a loader (e.g., 'Build.exe'), employs a multi-stage self-unpacking sequence and performs environmental reconnaissance. It retrieves encrypted instructions from immutable smart contracts via JSON-RPC requests to public nodes, decrypting the payloads using a weak PBKDF2/AES-GCM routine that relies on predictable salts derived from the contract addresses themselves. Once the C2 instructions are decrypted, the loader facilitates the download of secondary payloads, such as malicious DLLs or cryptocurrency miners, from code-hosting platforms like GitHub. The threat is notable for its reliance on legitimate decentralized RPC endpoints and Telegram APIs to obfuscate malicious traffic, making it significantly harder for traditional security controls to identify and block the infrastructure.

## Attack Chain

1. The Aeternum loader (Build.exe) is executed, initiating a multi-stage self-unpacking process in memory.
2. The malware establishes persistence by copying itself to the 'AppData\Local' directory and creating a shortcut (Wmi_Framework_APIKEY_wmsnet_&lt;random_value>.lnk) in the Startup folder.
3. The loader deobfuscates its configuration data to construct network strings for communication with Polygon blockchain RPC endpoints.
4. It sends JSON-RPC requests to public Polygon RPC nodes, targeting specific smart contract addresses using method 0xb68d1809 to retrieve encrypted commands.
5. The bot decrypts the retrieved C2 payload using a weak PBKDF2/AES-GCM routine keyed to the smart contract address.
6. The loader downloads additional malicious components, such as 'DotNetZip.dll' or cryptocurrency miners, from external GitHub repositories.
7. The secondary payloads execute and initiate secondary C2 communications with a Telegram bot using a hardcoded Telegram API token.
8. Stolen system information is packaged and exfiltrated to the C2 infrastructure via encrypted channels and the Telegram API.

## Impact

Aeternum presents a high risk due to its resilient, decentralized C2 structure, which complicates standard blocking at the DNS or IP level. Successful infections lead to the installation of various malicious tools, including RATs (e.g., XWorm), cryptocurrency miners (XMRig), and data exfiltration modules. Organizations compromised by this loader face the risk of persistent unauthorized remote access, resource hijacking, and theft of sensitive system information.

## Recommendation

* Enable process-creation logging to detect the creation of shortcuts in the Windows Startup directory that match the pattern 'Wmi_Framework_APIKEY_wmsnet_*.lnk'.
* Monitor network traffic for excessive JSON-RPC requests directed at known public Polygon RPC endpoints.
* Block or monitor egress traffic to 'api.telegram.org' originating from unauthorized non-business processes.
* Deploy endpoint detection and response (EDR) solutions to identify and alert on suspicious binaries spawned from the 'AppData\Local' directory, specifically those mimicking common administrative tools like 'wmiframework.exe'.
