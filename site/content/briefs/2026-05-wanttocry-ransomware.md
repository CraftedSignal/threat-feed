---
title: WantToCry Ransomware Exploits SMB for Remote Encryption
slug: 2026-05-wanttocry-ransomware
description: The WantToCry ransomware exploits exposed SMB services via brute-force for initial access, then exfiltrates files for remote encryption, rewriting the encrypted files to the original locations, demanding ransom payments from $400 to $1,800.
date: "2026-05-19T12:05:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - smb
  - wanttocry
vendors:
  - Microsoft
  - ISPsystem
  - Shodan
  - Censys
  - Telegram
products:
  - Windows Server 2016
  - Windows Server 2019
  - Shodan
  - Censys
  - Telegram
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.sophos.com/en-us/blog/wanttocry-ransomware-remotely-encrypts-files
rules:
  - title: Detect External IP Writing WantToCry Ransom Note via SMB
    description: Detects a host writing a file named '!Want_To_Cry.txt' to a share via SMB from external IP.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - file_event
      - windows
  - title: Detect SMB Brute Force Attempts
    description: Detects multiple failed SMB login attempts from the same source IP address, indicating potential brute-force activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1110.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

WantToCry ransomware, named after the infamous WannaCry worm, targets organizations with internet-exposed SMB services. Unlike WannaCry, WantToCry is not self-propagating but uses brute-force attacks against exposed SMB services on ports 139 and 445. After gaining access, it exfiltrates files via authenticated SMB sessions to attacker-controlled infrastructure where they are encrypted. The encrypted files are then rewritten back to the victim's system using the same SMB sessions. This operation minimizes the detection surface, as it doesn't involve local malware execution or post-compromise activity beyond file exfiltration and rewriting. The attackers leave ransom notes named `!Want_To_Cry.txt` and append the `.want_to_cry` suffix to encrypted files. Observed ransom demands ranged from $400 to $1,800.

## Attack Chain

1.  The attackers scan the internet for systems with open SMB ports (139 and 445) using reconnaissance services like Shodan and Censys.
2.  They attempt to gain access to targeted networks via automated brute-force attacks against the exposed SMB services.
3.  Upon successful authentication using compromised or weak credentials, the attackers initiate file exfiltration via authenticated SMB sessions.
4.  The exfiltrated files are then transferred to attacker-controlled infrastructure.
5.  On the attacker-controlled systems, the files are encrypted.
6.  The encrypted files are written back to the original locations on the victims' systems via the same authenticated SMB sessions.
7.  A ransom note named `!Want_To_Cry.txt` is dropped on the affected systems.
8.  The attackers demand ransom payment via qTox or Telegram, ranging from $400-$1800, for the decryption keys, with the objective of financial gain.

## Impact

WantToCry ransomware can lead to significant data loss and operational disruption for affected organizations. While the ransom demands ($400-$1800) are relatively low, the impact of data encryption can still be severe. The attacks are focused on systems with exposed SMB services, potentially limiting the scope of encryption. The primary targets appear to be organizations that have misconfigured or inadequately secured SMB services directly exposed to the internet.

## Recommendation

*   Monitor network traffic for sustained SMB read and write operations originating from external IP addresses, especially those from unusual geographic locations, using a network intrusion detection system (IDS) or firewall logs.
*   Implement account lockout policies and multi-factor authentication (MFA) for SMB services to prevent brute-force attacks; monitor authentication logs for repeated failed login attempts.
*   Deploy file integrity monitoring (FIM) solutions to detect unauthorized modification of files, particularly the creation of ransom notes named `!Want_To_Cry.txt`.
*   Block the listed IOCs (IP addresses) at your network perimeter to prevent communication with known attacker infrastructure.
*   Enable Sysmon process creation logging with network connection monitoring to enhance visibility into SMB activity for the rules below.
