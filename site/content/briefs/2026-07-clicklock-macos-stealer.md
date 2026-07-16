---
title: ClickLock macOS Stealer Uses Coercive App Killing to Force Password Entry
slug: 2026-07-clicklock-macos-stealer
description: The ClickLock macOS infostealer employs a unique coercive tactic by repeatedly killing essential macOS applications, such as Finder and Dock, every 210 milliseconds until the victim provides their login password, leading to the exfiltration of sensitive credentials and cryptocurrency wallets.
date: "2026-07-16T13:19:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - macos
  - infostealer
  - credential-theft
  - persistence
  - social-engineering
  - data-exfiltration
  - malware
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: It arrives as a command pasted into Terminal
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: installs two LaunchAgents and quietly exits. At the next login, Finder... start dying... The first fires the 210-millisecond kill loop until a password lands. The second launches its own kill loop
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: On macOS, the binary lands as iCloud in ~/Library/Application Support/iCloudsync and the process runs as SystemUIServerl, one letter off the real one.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: A completed run leaves the operator holding the validated macOS login password, Chrome's Safe Storage AES key, and a ZIP with browser credentials and cookies... and the Keychain
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Type it, and the machine gives up the Keychain, the browser credentials, and the crypto wallets.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: A completed run leaves the operator holding... a ZIP with browser credentials and cookies, crypto wallet extension storage, desktop wallet files, password manager vaults, the Keychain, shell history, and FileZilla's saved server credentials.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The backdoor, goyim... Its authors pitch the gs-netcat component as an encrypted reverse backdoor that needs no C2 server of its own. It rides a relay instead. Group-IB traced this copy to an operator relay at gsnc[.]eu:67
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1571
    technique_name: Non-Standard Port
    evidence: Group-IB traced this copy to an operator relay at gsnc[.]eu:67
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: the haul leaves through three Telegram bots. Group-IB observed no dedicated command-and-control infrastructure.
    confidence_band: high
references:
  - https://thehackernews.com/2026/07/new-clicklock-macos-stealer-kills-apps.html
iocs:
  - type: domain
    value: gsnc[.]eu
  - type: domain
    value: gsocket.io
ioc_counts:
  domain: 2
rules:
  - title: Detect ClickLock Stealer Payload Download via curl piped to bash
    description: Detects the ClickLock macOS stealer's initial payload download where 'curl' output is piped directly to 'bash', often using deceptive file extensions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.004
      - T1059.004
    data_sources:
      - process_creation
      - macos
  - title: Detect ClickLock Stealer LaunchAgent Persistence File Creation
    description: Detects the creation of specific LaunchAgent .plist files by the ClickLock macOS stealer for persistence across reboots or logins.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
  - title: Detect ClickLock Stealer Malicious Process Execution
    description: Detects the execution of the ClickLock macOS stealer's primary coercive and exfiltration component, masquerading as a system process.
    platform: sigma
    severity: critical
    tactics:
      - collection
      - execution
    techniques:
      - T1036.003
      - T1537
    data_sources:
      - process_creation
      - macos
rules_count: 3
---

The ClickLock macOS infostealer, identified by Group-IB, is actively targeting macOS users in at least 33 countries since May 2026, with over half of the attacks in Europe. This malware is delivered when a victim pastes a malicious command into Terminal, which initially presents a fake Cloudflare CAPTCHA and an `osascript` dialog to trick users into entering their password. If the user cancels this initial prompt, ClickLock establishes persistence by installing two LaunchAgents (`com.authirity.plist` and `com.chromer.plist`). Upon the next login, it initiates a highly aggressive coercion loop, killing critical macOS applications like Finder, Dock, Spotlight, and browsers every 210 milliseconds, along with repeatedly querying the Keychain for Chrome's Safe Storage key via a real macOS prompt, effectively holding the system hostage until the password is provided. The final objective is comprehensive data exfiltration, including browser credentials, cryptocurrency wallets, password manager vaults, and the entire Keychain.

## Attack Chain

1. The victim pastes a malicious command into the macOS Terminal application, initiating the execution of a `script.sh` orchestrator.
2. The `script.sh` disables keyboard interrupts, hides the cursor, and displays a fake Cloudflare CAPTCHA over a progress bar to reassure the victim while downloading additional payloads.
3. The orchestrator script uses `curl` piped into `bash` to download four payloads from compromised websites, some ending with deceptive extensions like `.jpg`, `.txt`, or `.css`.
4. A soft ask for the user's password is made via an `osascript` dialog, which uses a downloaded Apple icon and the victim's real username, validating the input using `dscl /Local/Default -authonly`.
5. If the victim cancels the initial password dialog, the script drops two LaunchAgents, `com.authirity.plist` and `com.chromer.plist`, into `~/Library/LaunchAgents/` and loads them using `launchctl` for persistence.
6. Upon subsequent login, one LaunchAgent activates a malicious process named `SystemUIServerl` (note the lowercase 'l') from `~/Library/Application Support/iCloudsync`, which begins killing critical macOS applications (Finder, Dock, SystemUIServer, NotificationCenter) every 210 milliseconds for extended periods.
7. The other LaunchAgent continuously queries the macOS Keychain for Chrome's Safe Storage key, triggering a legitimate, persistent password prompt that holds the desktop hostage.
8. Once the victim types their password, the stealer exfiltrates a wide range of sensitive data including the macOS login password, Keychain contents, browser credentials and cookies, crypto wallet data, password manager vaults, shell history, and FileZilla credentials via Telegram bots, while also installing a `goyim` reverse shell for continued access.

## Impact

The ClickLock stealer has impacted at least 100 targets across 33 countries since May 2026, primarily in Europe. A successful attack results in the complete compromise of the victim's digital identity and financial assets. Attackers gain access to the macOS login password, enabling further system compromise. They exfiltrate sensitive data including browser-saved passwords and cookies, cryptocurrency wallet files, password manager vaults, SSH/shell history, and FileZilla credentials. The persistent app-killing loop creates a severe usability impact, effectively rendering the system unusable until the victim complies, potentially leading to significant data loss, financial fraud, and identity theft. The presence of a backdoor (`goyim` reverse shell) allows long-term access to the compromised machine.

## Recommendation

* Deploy a Sigma rule to detect `curl` commands piped into `bash` for suspicious file extensions (`.jpg`, `.txt`, `.css`) as an indicator of initial payload download.
* Implement a Sigma rule to monitor for the creation of LaunchAgent `.plist` files named `com.authirity.plist` or `com.chromer.plist` in user `~/Library/LaunchAgents/` directories, as this indicates persistence.
* Use a Sigma rule to detect `launchctl load` operations targeting `com.authirity.plist` or `com.chromer.plist` as this signifies the activation of the persistence mechanism.
* Create a Sigma rule to alert on the execution of a process named `SystemUIServerl` (lowercase 'l') from `~/Library/Application Support/iCloudsync/`, as this is the primary malicious component.
* Educate users to recognize that legitimate Cloudflare CAPTCHA checks and Apple password prompts do not appear as dialogs from the Terminal and to never paste arbitrary commands from untrusted sources.
* Advise users who experience the coercive app-killing behavior to immediately power down their Mac by holding the power button, then restart in Safe Mode (using the appropriate procedure for Intel or Apple Silicon Macs) to perform cleanup.
