---
title: Windows User Account Creation via net.exe
slug: 2024-01-09-user-account-creation
description: Attackers may create new accounts on Windows systems using `net.exe` to maintain access and establish persistence, which this detection identifies.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - account-creation
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://attack.mitre.org/techniques/T1136/
  - https://attack.mitre.org/techniques/T1136/001/
  - https://attack.mitre.org/techniques/T1136/002/
rules:
  - title: Detect Windows User Account Creation via net.exe
    description: Detects the creation of new user accounts via net.exe, a technique commonly used for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136
      - T1136.001
      - T1136.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows User Account Creation - net1.exe
    description: Detects the creation of new user accounts via net1.exe, an older version of net.exe.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136
      - T1136.001
      - T1136.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows Account Creation - Adding user to Local Group
    description: Detects when a newly created user is added to a privileged local group, indicating potential privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1136
      - T1136.001
      - T1136.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers may create new accounts (both local and domain) to maintain access to victim systems. This is often done after initial compromise to ensure continued access even if initial entry points are closed. This rule identifies the usage of `net.exe` (and `net1.exe`) to create new accounts on Windows systems. The rule specifically looks for the `user` and `/add` parameters in the command line arguments. The timeframe analyzed is the last 9 minutes based on the `from` field in the original rule. This activity, while potentially legitimate, warrants investigation due to its potential for malicious use by threat actors aiming for persistence. The detection logic excludes scenarios where the parent process is also `net.exe` to reduce noise from legitimate administrative tasks.

## Attack Chain

1. An attacker gains initial access to a Windows system, potentially through exploitation of a vulnerability or stolen credentials.
2. The attacker executes `net.exe` with the `user` and `/add` arguments to create a new local or domain user account.
3. The new user account is configured with specific privileges, potentially adding it to local administrator groups.
4. The attacker uses the newly created account to log into the system, bypassing existing security controls.
5. The attacker uses the new account to install malware or other malicious tools on the system.
6. The attacker establishes persistence by adding the newly created account to startup programs or scheduled tasks.
7. The attacker uses the persistent access to move laterally within the network, compromising additional systems.
8. The attacker achieves their ultimate objective, such as data exfiltration or ransomware deployment, leveraging the established persistence.

## Impact

Successful creation of malicious user accounts can lead to persistent access within a compromised environment. While this event may be legitimate, unauthorized account creation can allow attackers to maintain access to systems even after initial vulnerabilities are patched or detected. Depending on the privileges granted to the created account, the impact can range from limited access to complete control over the compromised system and potentially the entire domain. This can facilitate data theft, disruption of services, or the deployment of ransomware.

## Recommendation

*   Deploy the Sigma rule `Detect Windows User Account Creation via net.exe` to your SIEM to detect suspicious account creation attempts.
*   Enable Sysmon process creation logging to ensure the necessary data is available for the Sigma rule to function correctly.
*   Investigate all instances flagged by the Sigma rule, paying close attention to the parent processes and the context of the account creation.
*   Correlate detected events with other suspicious activities on the host or network to identify potentially compromised systems.
*   Review existing account creation policies and procedures to ensure they are adequate and enforced.
*   Implement multi-factor authentication for all user accounts to mitigate the risk of unauthorized access.
*   Monitor security logs from Windows Security Event Logs for event IDs related to account creation (4720, 4722, 4723, 4724, 4725).
