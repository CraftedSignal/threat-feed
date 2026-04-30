---
title: Git for Windows NTLM Hash Leak Vulnerability (CVE-2026-32631)
slug: 2026-04-git-ntlm-hash-leak
description: Git for Windows versions prior to 2.53.0.windows.3 are vulnerable to NTLM hash theft by attackers who can trick users into cloning malicious repositories or checking out malicious branches, leading to potential credential compromise.
date: "2026-04-15T18:17:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - credential-access
  - windows
  - git
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
cves:
  - id: CVE-2026-32631
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32631
rules:
  - title: Detect Git Process Spawning Cmd with /c net use
    description: Detects Git process spawning cmd.exe to execute net use command, which can be an indicator of NTLM authentication attempt
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - process_creation
      - windows
  - title: Detect Git Network Connection to Uncommon Ports
    description: Detects Git process making network connections to uncommon ports, indicating potential malicious repository access
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Git for Windows versions before 2.53.0.windows.3 are susceptible to a vulnerability (CVE-2026-32631) that exposes users' NTLM hashes to malicious actors. This occurs when a user interacts with a specially crafted Git repository or branch hosted on an attacker-controlled server. The vulnerability stems from the lack of sufficient protections against unauthorized NTLM authentication requests during Git operations. The attack doesn't require user interaction beyond the initial clone or checkout. Successful exploitation allows attackers to capture NTLMv2 hashes, which, while computationally expensive, can be brute-forced to recover user credentials. This vulnerability was patched in Git for Windows version 2.53.0.windows.3.

## Attack Chain

1.  Attacker sets up a malicious Git repository on a server under their control. This repository contains a Git configuration that triggers an NTLM authentication request to the attacker's server.
2.  The attacker crafts a social engineering campaign to entice the victim to clone the malicious repository using the `git clone` command.
3.  Alternatively, the attacker compromises an existing Git repository and adds a malicious branch. The victim is then tricked into checking out this branch using `git checkout`.
4.  When the victim clones the repository or checks out the malicious branch, Git for Windows attempts to authenticate with the attacker's server using the NTLM protocol.
5.  The victim's NTLMv2 hash is sent to the attacker's server during the NTLM authentication handshake.
6.  The attacker captures the NTLMv2 hash from the authentication traffic.
7.  The attacker initiates an offline brute-force attack against the captured NTLMv2 hash.
8.  Upon successful brute-forcing, the attacker recovers the victim's credentials and can use them to access other resources.

## Impact

Successful exploitation of CVE-2026-32631 allows attackers to steal user credentials. The impact includes unauthorized access to sensitive data, systems, and applications accessible with the compromised credentials. The number of potential victims is directly related to the number of users running vulnerable versions of Git for Windows who interact with malicious repositories or branches. Targeted sectors are broad, encompassing any organization using Git for Windows for software development and version control.

## Recommendation

*   Upgrade Git for Windows to version 2.53.0.windows.3 or later to remediate CVE-2026-32631.
*   Implement network monitoring to detect NTLM authentication attempts originating from Git processes to unusual or external destinations.
*   Deploy the Sigma rule "Detect Git Process Spawning Cmd with /c net use" to detect potential NTLM authentication attempts and adjust it to monitor outbound network connections from `git.exe` using NTLM.
