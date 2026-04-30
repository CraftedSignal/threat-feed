---
title: libssh Insecure Configuration Allows Local MITM Attacks (CVE-2025-14821)
slug: 2026-04-libssh-mitm
description: CVE-2025-14821 in libssh allows local man-in-the-middle attacks, SSH downgrade attacks, and trusted host manipulation due to insecure default configuration loading from a world-writable directory on Windows.
date: "2026-04-07T17:16:25Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - libssh
  - mitm
  - windows
  - cve-2025-14821
  - insecure-configuration
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2025-14821
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-14821
rules:
  - title: Detect Creation of C:\etc Directory by Non-System Processes
    description: Detects the creation of the C:\etc directory, which could be an indicator of CVE-2025-14821 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - file_event
      - windows
  - title: Detect Modification of SSH Config in C:\etc
    description: Detects modification of ssh_config file in the C:\etc directory.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A critical vulnerability, CVE-2025-14821, has been identified in the libssh library. This flaw arises from an insecure default configuration on Windows systems. Specifically, libssh automatically loads configuration files from the `C:\etc` directory. Critically, this directory can be created and modified by unprivileged local users. This allows a malicious local user to manipulate the SSH configuration, facilitating man-in-the-middle attacks, downgrading connection security, and manipulating trusted host information. Successful exploitation grants attackers the ability to intercept and potentially modify SSH communications, posing a significant risk to data confidentiality, integrity, and availability.

## Attack Chain

1.  Attacker creates the directory `C:\etc` if it does not already exist.
2.  Attacker creates a malicious SSH configuration file (e.g., `ssh_config`) within the `C:\etc` directory. This configuration can specify settings to downgrade encryption or redirect connections.
3.  A legitimate user initiates an SSH connection using an application that leverages the vulnerable libssh library.
4.  libssh automatically loads the attacker-controlled configuration file from `C:\etc\ssh_config`.
5.  The malicious configuration settings are applied, potentially downgrading the encryption algorithm used for the SSH connection.
6.  The attacker intercepts the SSH traffic, performing a man-in-the-middle attack due to the weakened encryption or connection redirection.
7.  The attacker can now eavesdrop on or modify the SSH communication, gaining unauthorized access to sensitive information or injecting malicious commands.
8.  Attacker maintains persistent access or exfiltrates sensitive data obtained through the compromised SSH session.

## Impact

Successful exploitation of CVE-2025-14821 allows a local attacker to perform man-in-the-middle attacks on SSH connections. This can lead to the compromise of sensitive data transmitted over SSH, such as credentials, configuration files, or confidential documents. The ability to manipulate trusted host information further exacerbates the risk, potentially allowing attackers to impersonate legitimate servers. The vulnerability affects any Windows system using a vulnerable version of libssh and could impact organizations across all sectors that rely on SSH for secure communication and remote administration.

## Recommendation

*   Monitor for the creation or modification of files within the `C:\etc` directory, particularly configuration files like `ssh_config`, using file integrity monitoring (FIM) rules on Windows systems.
*   Implement the Sigma rule provided to detect the creation of the `C:\etc` directory by non-system processes.
*   Restrict write access to the `C:\etc` directory and its contents using appropriate file system permissions on Windows systems.
