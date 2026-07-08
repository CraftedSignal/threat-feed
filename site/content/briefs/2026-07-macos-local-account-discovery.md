---
title: macOS Local System Accounts Discovery
slug: 2026-07-macos-local-account-discovery
description: Adversaries leverage various built-in macOS utilities and commands, such as `dscl`, `dscacheutil`, `cat /etc/passwd`, `id`, `lsof`, `who`, `w`, `users`, `last`, `ls /Users`, `defaults`, and `plutil`, to enumerate local system accounts, facilitating lateral movement or privilege escalation within a compromised macOS environment.
date: "2026-07-08T23:15:55Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - reconnaissance
  - macos
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Detects enumeration of local system accounts on MacOS systems.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1087.001/T1087.001.md
  - https://ss64.com/osx/dscl.html
  - https://ss64.com/mac/dscacheutil.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_local_account.yml
rules:
  - title: macOS Local System Accounts Discovery
    description: Detects enumeration of local system accounts on macOS systems using various built-in utilities, indicative of reconnaissance for lateral movement or privilege escalation.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087.001
    data_sources:
      - process_creation
      - macos
rules_count: 1
---

This brief highlights the post-exploitation technique of discovering local system accounts on macOS environments. Threat actors, once gaining initial access, commonly employ a range of native macOS commands and utilities to map out the system's user landscape. These tools include directory service commands like `dscl` and `dscacheutil`, file system commands such as `cat` for `/etc/passwd`, and user enumeration commands like `id`, `who`, `w`, `users`, and `last`. Additionally, attackers may inspect home directories via `ls /Users` or system preference files using `defaults` and `plutil` to gather information about logged-in users or login configurations. The primary motivation for this reconnaissance is to identify potential targets for lateral movement, privilege escalation, or to understand the scope of user access on the compromised machine. This activity is a crucial step in the adversary's playbook, enabling them to expand their foothold and achieve their ultimate objectives, which could range from data exfiltration to deploying malware.

## Attack Chain

1. **Initial Access (Assumed)**: An adversary gains an initial foothold on a macOS system through an unspecified mechanism (e.g., malware execution, compromised credentials, exploitation of a vulnerability).
2. **Execute `dscl` for User Listing**: The attacker executes `dscl . -list /Users` to list all local user accounts present on the system.
3. **Execute `dscacheutil` for User Information**: The attacker runs `dscacheutil -q user` to query the directory service cache for detailed user information.
4. **Inspect System Files for Accounts**: The attacker uses commands like `cat /etc/passwd`, potentially piped through `awk` or `grep`, to identify user accounts and their associated UIDs.
5. **Enumerate Current and Past Logged-in Users**: Commands such as `id`, `who`, `w`, `users`, and `last` are used to determine currently active sessions, user IDs, and recent login history.
6. **Scan User Home Directories**: The adversary lists the contents of the `/Users` directory using `ls /Users` to identify existing user profiles.
7. **Inspect Login Window Preferences**: The attacker uses `defaults read /Library/Preferences/com.apple.loginwindow` or `plutil -p /Library/Preferences/com.apple.loginwindow.plist` to extract login window configurations, which might reveal additional user or system details.
8. **Information Consolidation and Next Steps**: The gathered account information is then used to plan further actions, such as targeting specific users for credential compromise, attempting privilege escalation, or facilitating lateral movement to other systems.

## Impact

Successful enumeration of local system accounts provides adversaries with critical intelligence regarding potential targets for further compromise. This information can be leveraged to craft more effective phishing campaigns, identify users with elevated privileges, or determine accounts that are infrequently used but still active, making them ideal for persistence or lateral movement. The ultimate impact can range from expanded access within the network, unauthorized data exfiltration, to the deployment of ransomware or other destructive payloads if administrative accounts are identified and compromised. While this specific activity is informational, it directly contributes to more severe stages of an attack.

## Recommendation

* Deploy the Sigma rule "macOS Local System Accounts Discovery" to your SIEM to detect suspicious enumeration activity.
* Ensure macOS process creation logging is enabled for all endpoints to allow the above rule to function effectively.
* Review alerts generated by this rule to identify legitimate administrative activities versus potential malicious reconnaissance.
* Implement strong authentication mechanisms and privilege access management (PAM) solutions to limit the impact of compromised credentials identified via such discovery activities.
