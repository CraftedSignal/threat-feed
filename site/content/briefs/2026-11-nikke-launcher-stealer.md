---
brief_id: brief-2026-11-12-nikke-launcher-stealer
event_id: brief-2026-11-12-nikke-launcher-stealer
revision: 1
activity_at: "2026-11-12T16:22:08Z"
title: NIKKE Game Launcher Compromised for Info Stealer Delivery
slug: 2026-11-nikke-launcher-stealer
description: Unknown actors compromised the NIKKE game launcher's server-pushed task channel to deliver a Lua-based info stealer disguised as a log file, enabling the theft of browser credentials, crypto-wallet data, and developer secrets.
date: "2026-11-12T16:22:08Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.bitdefender.com/en-us/blog/labs/nikke-game-launcher-malware
  observed_at: "2026-10-30T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
tags:
  - credential-theft
  - info-stealer
  - supply-chain
vendors:
  - Level Infinite
  - Shift Up
products:
  - NIKKE game launcher
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1555.003
    technique_name: Credentials from Web Browsers
    evidence: Running inside the launcher's embedded browser engine, the k2f-agent can harvest saved passwords and cookies from Chrome, Edge, and Opera.
    confidence_band: high
references:
  - https://www.bitdefender.com/en-us/blog/labs/nikke-game-launcher-malware
action_plan:
  hunt_leads:
    - lead: Monitor for non-browser processes, specifically game launchers or embedded CEF/Electron frameworks, performing file I/O operations on browser credential stores. Look for processes opening files named 'Login Data', 'Login Data for Account', 'Local State', or '.ldb' files within browser profiles (e.g., Chrome, Edge, Opera).
      technique_id: T1555.003
      data_needed:
        - Endpoint process file handle telemetry
        - EDR file access events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: A non-browser process (in particular a game launcher) opening ... \User Data...\Login Data, Login Data For Account, Local State or extension Local Extension Settings*.ldb files.
---

Bitdefender researchers identified a credential theft campaign targeting users of the Goddess of Victory: NIKKE game launcher. Attackers leveraged the launcher's server-pushed task channel to deliver a malicious payload, dubbed k2f-agent, which executed within the context of the signed launcher process. The payload was obfuscated LuaJIT bytecode masquerading as a standard log file. The k2f-agent registered a service via the launcher's embedded JS-to-native bridge to perform credential harvesting and exfiltration. The malware leaves minimal artifacts on disk, as malicious code execution occurred primarily in unbacked heap memory.

## Attack Chain
1. The launcher queried its backend for tasks upon login.
2. The backend returned a task including a URL to a payload disguised as a log file.
3. The launcher's downloader fetched and saved the payload to a local log directory.
4. The launcher's Lua VM loaded the bundle, which registered a new service ('k2f_chan') via the launcher's JS-to-native bridge.
5. Remote operators issued commands over this bridge to harvest data.
6. Exfiltration occurred via the launcher's existing outbound telemetry infrastructure.

## Impact
The stealer harvested browser passwords, cookies, SSH keys, GPG keys, Git credentials, Kubernetes configs, environment variables, Windows Credential Manager entries, and cryptocurrency wallet data from MetaMask, Phantom, Coinbase Wallet, Keplr, and TronLink. The entire process from download to cleanup typically completed in under 10 minutes.

## Recommendation
Users who utilized the affected launcher during the incident window should consider their machines compromised. Recommended actions include rotating all stored browser passwords, generating new seed phrases for crypto-wallets on clean hardware, and rotating all stored developer secrets (SSH keys, GPG keys, Git credentials, etc.).
