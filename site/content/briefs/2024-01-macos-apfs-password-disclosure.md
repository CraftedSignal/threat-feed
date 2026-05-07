---
title: macOS High Sierra APFS Password Disclosure Vulnerability (CVE-2017-7149)
slug: 2024-01-macos-apfs-password-disclosure
description: CVE-2017-7149 is a vulnerability in macOS High Sierra (10.13) where the password for an encrypted APFS volume is stored as plain text in the password hint, potentially allowing a local attacker to gain unauthorized access.
date: "2024-01-03T15:00:00Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - apfs
  - password-disclosure
  - privilege-escalation
  - macos
vendors:
  - Apple
products:
  - macOS High Sierra (10.13)
  - Disk Utility.app
affected_os:
  - macos 10.13
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2017-7149
    cvss: 7.8
    epss: 0.00086
references:
  - https://objective-see.org/blog/blog_0x23.html
rules:
  - title: Detect Disk Utility App Execution
    description: Detects execution of the Disk Utility application, which may indicate attempts to create or mount encrypted APFS volumes.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - macos
  - title: Detect 'Show Hint' Click in Disk Utility Password Prompt
    description: Detects when the 'Show Hint' button is clicked in Disk Utility, which may indicate attempts to exploit CVE-2017-7149.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1003
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

CVE-2017-7149 is a critical vulnerability affecting macOS High Sierra (10.13) related to the handling of passwords for encrypted Apple File System (APFS) volumes. Discovered by Matheus Mariano, the vulnerability exposes the password as plain text within the password hint field. This occurs during the creation of an encrypted APFS volume using Disk Utility.app. While Apple has addressed this issue with a patch, the flaw allows a local attacker to potentially bypass encryption and access sensitive data stored within the encrypted volume. The vulnerability stems from an apparent mixup between the password and password hint fields during the volume creation process.

## Attack Chain

1.  A local attacker gains access to a macOS High Sierra (10.13) system.
2.  The attacker opens Disk Utility.app.
3.  The attacker initiates the process of mounting an encrypted APFS volume.
4.  The system prompts the attacker for the password to unlock the volume.
5.  The attacker clicks the 'Show Hint' button in the password prompt dialog.
6.  Instead of the intended password hint, the system displays the actual password for the encrypted volume in plain text.
7.  The attacker uses the displayed password to unlock and mount the encrypted APFS volume.
8.  The attacker gains full access to all data stored within the decrypted APFS volume.

## Impact

Successful exploitation of CVE-2017-7149 results in the unauthorized disclosure of the password for an encrypted APFS volume. A local attacker can leverage this to bypass encryption, mount the volume, and gain access to all sensitive data stored within. This vulnerability impacts macOS High Sierra (10.13) users who utilize encrypted APFS volumes for data protection. The number of affected users is unknown, but the potential for data compromise is significant for any user relying on APFS encryption on the affected operating system version.

## Recommendation

*   If running an unpatched macOS High Sierra (10.13) system, upgrade to a patched version to remediate CVE-2017-7149.
*   Enable system integrity protection (SIP) to make debugging and tampering with system processes more difficult for attackers.
*   Monitor for suspicious activity involving Disk Utility.app, specifically attempts to mount or access encrypted APFS volumes. Deploy the Sigma rule to detect unusual process execution patterns related to Disk Utility.app.
*   Audit existing APFS volumes for password hints that may contain sensitive information due to this vulnerability.
