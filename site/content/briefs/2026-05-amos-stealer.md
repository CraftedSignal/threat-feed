---
title: AMOS (Atomic macOS Stealer) Malware Targeting macOS Systems
slug: 2026-05-amos-stealer
description: The Atomic macOS Stealer (AMOS) is a prevalent malware-as-a-service targeting macOS, distributed via social engineering techniques like ClickFix ruses and fake installers, designed to steal sensitive data such as credentials and cryptocurrency wallets, leading to potential account compromise and further attacks.
date: "2026-05-14T11:40:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - macos
  - amos
  - infostealer
vendors:
  - Apple
  - Microsoft
products:
  - Firefox
  - Chrome
  - Chromium
  - macOS Keychain
  - Ledger Wallet
  - Trezor Suite
  - Apple Notes
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1056
    technique_name: Input Capture
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.sophos.com/en-us/blog/why-amos-matters-the-macos-malware-stealing-data-at-scale
rules:
  - title: Detect AMOS Stealer Bootstrap Execution
    description: Detects the execution of a bootstrap script commonly used by AMOS stealer using base64 decoding and bash execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
  - title: Detect AMOS Stealer Password File Creation
    description: Detects the creation of a hidden password file by AMOS stealer under the user's home directory.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1056
    data_sources:
      - file_event
      - macos
  - title: Detect AMOS Stealer Network Connection to C2
    description: Detects network connections to known AMOS command-and-control servers.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - macos
rules_count: 3
---

The Atomic macOS Stealer (AMOS) is a malware-as-a-service (MaaS) that has become a significant threat to macOS systems. Sophos X-Ops reported that AMOS accounted for almost 40% of their macOS protection updates in 2025, more than double any other macOS malware family. It has been tracked since at least April 2023 and is distributed through social engineering techniques, including ClickFix ruses, fake installers, and lures related to AI models. AMOS is designed to steal Keychain data, browser credentials, cookies, autofill information, and other high-value artifacts like cryptocurrency wallet data, enabling rapid account takeover and follow-on attacks. Defenders have observed repeated password prompting until the victim provides their macOS password, which is then used to perform privileged actions.

## Attack Chain

1. The user is tricked into executing a command in the Terminal through social engineering (ClickFix).
2. A first-stage bootstrap script is downloaded from `hxxps://sphereou[.]com/cleanera` and executed using `echo <b64> | base64 -d | bash`.
3. The malware prompts the user for their macOS system password and validates it locally using `dscl . -authonly "$username" "$password"`, storing the password in a hidden file.
4. A second-stage payload is downloaded from `hxxps[://]sphereou[.]com/cleaner3/update` and saved to `/tmp/update`. Extended attributes are removed using `xattr -c /tmp/update`, and the file is executed.
5. Anti-analysis routines check for virtualized environments (QEMU, VMware, KVM) by querying `system_profiler` data via `osascript`.
6. The malware collects user and system data, including Keychain database, macOS password, Firefox and Chrome profile data, Apple Notes, extension storage, host and system profile data, and cryptocurrency-related information.
7. Stolen data is archived and prepared for exfiltration to attacker infrastructure. Exfiltration targets include IP address 38[.]244[.]158[.]56.
8. Persistence is established using LaunchDaemon. The system registers with a command-and-control (C2) server such as `hxxp://45[.]94[.]47[.]204/api/join/` and `hxxp://45[.]94[.]47[.]204/api/tasks/`.

## Impact

AMOS steals sensitive information like credentials, cookies, autofill data, and cryptocurrency wallet information. It can lead to account compromise, financial loss, and further attacks. Sophos reported that AMOS accounted for almost 40% of their macOS protection updates in 2025.

## Recommendation

*   Monitor process creations for execution of commands using `echo <b64> | base64 -d | bash` via the Sigma rule "Detect AMOS Stealer Bootstrap Execution".
*   Monitor network connections to the C2 IP addresses `45[.]94[.]47[.]204` and the data exfiltration IP address `38[.]244[.]158[.]56` at the firewall or proxy level.
*   Monitor file creation events for the creation of hidden password files under `/Users/$username/.pass` via the Sigma rule "Detect AMOS Stealer Password File Creation".
