---
title: Detection of macOS Keychain Credential Harvesting
slug: 2026-10-macos-keychain-dumping
description: This brief details methods used by attackers to harvest sensitive credentials from macOS Keychain databases using native utilities or direct file access.
date: "2026-10-12T17:52:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - macos
  - post-exploitation
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Detects command-line attempts to access or dump macOS Keychain data using native utilities or direct file access.
    confidence_band: high
rules:
  - title: Detect MacOS Keychain Data Access
    description: Detects command-line attempts to access or dump macOS Keychain data using the security utility or direct file manipulation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.001
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy process-level detection for /usr/bin/security and common file manipulation tools targeting Keychain paths.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection documentation
  hunt_leads:
    - lead: Search for historical process execution logs involving the 'security' binary with arguments 'dump-keychain' or 'find-certificate'.
      technique_id: T1555.001
      data_needed:
        - Endpoint process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Standard post-exploitation TTP
---

Adversaries targeting macOS environments frequently conduct credential harvesting as a post-exploitation activity to facilitate lateral movement and privilege escalation. This threat involves the unauthorized access or exfiltration of Keychain database files, which store sensitive information including application credentials, Wi-Fi passwords, system service accounts, and cryptographic certificates. Attackers typically utilize native macOS utilities such as the `security` command-line tool, specifically using arguments like `dump-keychain` or `find-certificate` to extract data. Alternatively, adversaries may perform direct file manipulation on Keychain databases located in `~/Library/Keychains/`, `/Library/Keychains/`, or `/Network/Library/Keychains/` using standard system tools like `cat`, `cp`, `dd`, or `mv`. Detecting these activities is critical for identifying active unauthorized access to system-stored secrets.

## Attack Chain

1. Attacker gains initial access to a macOS system via phishing, malicious software, or exploit.
2. Attacker establishes a shell session and performs local enumeration to identify stored secrets.
3. Attacker targets the user's login keychain or system-wide keychain files for access.
4. Attacker uses `/usr/bin/security dump-keychain -d` to attempt to export decrypted credentials.
5. Attacker executes `security find-certificate -p` to harvest certificates for further malicious use.
6. Attacker leverages file utilities such as `cp` or `dd` to copy `.keychain` database files to an accessible directory.
7. Attacker exfiltrates the database files to external infrastructure or parses them offline.
8. Attacker uses harvested credentials to escalate privileges or move laterally within the organization.

## Impact

Successful harvesting of Keychain data allows attackers to gain persistent access to sensitive services and accounts. Because the Keychain often contains credentials for cloud services, internal network infrastructure, and administrative tools, compromise often leads to full account takeover or further compromise of the internal network. The scope of impact is limited to the local system and the individual credentials stored within that specific user or system keychain.

## Recommendation

Prioritize monitoring for unauthorized execution of the `security` utility and unexpected access to Keychain directory paths.
- Deploy process monitoring (e.g., Osquery or Endpoint Security) to audit executions of `/usr/bin/security`.
- Implement monitoring for standard file manipulation tools (cat, cp, dd, mv) targeting files ending in `.keychain` within the standard macOS library paths.
- Baseline administrator activity to differentiate legitimate troubleshooting from malicious credential harvesting.
- Integrate the provided Splunk search logic into your SIEM to monitor for the specific process command-line arguments mentioned in the overview.
