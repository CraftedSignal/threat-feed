---
title: Linux SSH Persistence via Backdoored System User
slug: 2024-01-backdoored-ssh-user
description: Attackers can maintain unauthorized access to Linux systems by backdooring system user accounts with SSH keys, allowing persistent access even after password changes.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - ssh
  - linux
products:
  - Linux
  - SSH
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_ssh_via_backdoored_system_user.toml
rules:
  - title: Detect SSH Key Added to Authorized Keys
    description: Detects when an SSH key is added to an authorized_keys file, which could indicate a backdoored system user.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - file_event
      - linux
  - title: Detect SSH Key Generation
    description: Detects the use of ssh-keygen command, which may indicate attacker activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - persistence
    techniques:
      - T1098
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of SSH Configuration Files
    description: Detects changes to SSH configuration files.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Attackers targeting Linux systems may establish persistence by compromising existing system user accounts and adding unauthorized SSH keys. This method allows them to bypass standard authentication procedures and regain access to the system even after password resets. While the specific campaigns leveraging this technique are currently unclear, the risk is significant, as it grants persistent access and is difficult to detect without specific monitoring in place. The use of backdoored system users circumvents typical multi-factor authentication and account lockout policies, potentially granting long-term access to sensitive data and systems.

## Attack Chain

1.  Initial Access: Attacker gains initial access through an unstated vector (e.g., exploiting a web application vulnerability, or using stolen credentials).
2.  Privilege Escalation: The attacker escalates privileges to root or a privileged user, potentially using exploits (e.g., Dirty Pipe) or misconfigurations.
3.  Account Discovery: The attacker identifies potential system user accounts to backdoor (e.g., accounts without passwords or with weak passwords).
4.  SSH Key Generation: The attacker generates a new SSH key pair for persistent access using `ssh-keygen`.
5.  Key Installation: The attacker modifies the authorized_keys file (usually located at `/home/[username]/.ssh/authorized_keys`) of the targeted user to include the attacker's public key.
6.  Persistence Check: The attacker tests the SSH login using the newly added key to ensure successful access.
7.  Cleanup (Optional): The attacker removes traces of the key generation or modification from logs and command history, though this is not always done thoroughly.
8.  Lateral Movement/Data Exfiltration: With persistent access, the attacker moves laterally within the network, accesses sensitive data, and exfiltrates it.

## Impact

Compromised system user accounts can grant attackers long-term, stealthy access to critical systems. This can lead to data breaches, system downtime, and reputational damage. The number of victims and targeted sectors are unknown, but any organization relying on Linux systems for critical infrastructure is potentially at risk. Successful exploitation can result in complete system compromise and data exfiltration, causing significant financial and operational losses.

## Recommendation

*   Deploy the Sigma rule "Detect SSH Key Added to Authorized Keys" to identify suspicious modifications to `authorized_keys` files.
*   Monitor system logs for unusual SSH login activity, specifically logins using SSH keys instead of passwords (reference logsource: `linux` `auth.log`).
*   Regularly audit system user accounts for unauthorized SSH keys (using shell commands and scripts).
*   Enforce strong password policies and multi-factor authentication where possible to prevent initial compromise (related to initial access vector).
