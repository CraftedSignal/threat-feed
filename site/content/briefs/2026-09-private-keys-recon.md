---
title: Private Keys Reconnaissance Via Command Line Tools
slug: 2026-09-private-keys-recon
description: Adversaries utilize native Windows utilities to enumerate local file systems for improperly stored private keys and cryptographic credentials.
date: "2026-09-01T11:06:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Adversaries may search for private key certificate files on compromised systems for insecurely stored credential
    confidence_band: high
rules:
  - title: Detect Private Keys Reconnaissance via Command Line
    description: Detects recursive file search commands targeting common private key and certificate file extensions
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1552.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for recursive key searches
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting reconnaissance of private keys
  hunt_leads:
    - lead: Search command line logs for wide-scope 'dir' or 'Get-ChildItem' operations targeting known key extensions
      technique_id: T1552.004
      data_needed:
        - Process creation telemetry
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source highlights cmd and powershell as tools for reconnaissance
---

Adversaries frequently perform reconnaissance on compromised endpoints to identify sensitive cryptographic material stored in insecure locations. By leveraging standard command line interfaces and built-in Windows utilities, attackers can recursively search for common file extensions associated with private keys, PGP/GPG configurations, and certificates. This activity is a common precursor to credential theft and lateral movement, as these files may grant unauthorized access to remote services, encrypted data, or developer environments. Detecting this behavior is essential, as the tools used (cmd, PowerShell, findstr) are native to the operating system and often blend into normal administrative activity.

## Attack Chain

1. Attacker gains interactive command execution access on a Windows endpoint.
2. Attacker identifies potential directory paths of interest (e.g., user profiles, SSH configs, or development folders).
3. Attacker initiates a search for specific file extensions using `dir`, `Get-ChildItem`, or `findstr` /s.
4. The search targets extensions including .key, .pgp, .gpg, .ppk, .p12, .pem, .pfx, .cer, .p7b, or .asc.
5. Attacker observes command output to verify the presence of keys on the local disk.
6. Attacker exfiltrates or directly utilizes discovered private keys for persistence or unauthorized access.

## Impact

Successful reconnaissance of private keys leads to the compromise of identity-based assets, potential exfiltration of encrypted communications, and the bypass of multi-factor authentication systems that rely on certificate-based authentication. If attackers secure these keys, they can establish long-term persistence within development or infrastructure environments, leading to potential supply chain or data integrity breaches.

## Recommendation

Deploy detection rules to monitor for recursive file listing operations that target sensitive cryptographic file extensions.
- Implement the provided Sigma rule to alert on suspicious combinations of file search commands and key-related extensions.
- Review baseline administrative scripts in the environment to identify legitimate automated key management tasks and tune out noise.
- Use endpoint detection and response (EDR) telemetry to correlate the reconnaissance activity with subsequent suspicious file access or egress traffic.
