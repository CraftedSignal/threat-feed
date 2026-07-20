---
title: FileBrowser Username Normalization Collision Leads to Authorization Bypass
slug: 2026-07-filebrowser-username-collision
description: A critical authorization bypass vulnerability, CVE-2026-62685, in FileBrowser versions <= 2.63.16 enables an attacker to gain full read and write access to other users' files by exploiting a username normalization collision during self-registration, thus bypassing per-user isolation and allowing data tampering or exfiltration.
date: "2026-07-20T22:21:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - web-application
  - filebrowser
  - vulnerability
vendors:
  - FileBrowser
products:
  - FileBrowser <= 2.63.16
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An attacker can pick a username that normalizes onto a victim's directory (for example registering `alice/` or `al..ice` to land in `alice`'s home) and gain full read **and** write access to that victim's files.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This breaks per-user isolation. An attacker can pick a username that normalizes onto a victim's directory... and gain full read **and** write access to that victim's files.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1561
    technique_name: Disk Wipe
    evidence: the attacker can overwrite, rename, or delete the victim's files; the victim transparently sees the tampered content.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: an attacker registering a colliding username can read every file in a victim's home directory.
    confidence_band: med
cves:
  - id: CVE-2026-62685
    cvss: 8.1
    epss: 0.00323
references:
  - https://github.com/advisories/GHSA-7rc3-g7h6-22m7
---

FileBrowser, an open-source file manager, is affected by CVE-2026-62685, a high-severity authorization bypass vulnerability. This flaw, present in versions up to 2.63.16, allows an unauthenticated attacker to gain full read and write access to other users' files. The vulnerability stems from a collision in username normalization during the self-registration process when both `Signup=true` and `CreateUserDir=true` settings are enabled. The `cleanUsername()` function, responsible for sanitizing usernames before creating user home directories, can map different input usernames to the same directory name. Attackers can register a crafted username (e.g., `alice/`, `al..ice`) that normalizes to an existing victim's home directory (e.g., `alice`), effectively sharing the same storage. This bypasses FileBrowser's per-user isolation, enabling data exfiltration, tampering, or deletion. Defenders should understand this vulnerability as it directly impacts data confidentiality and integrity for organizations using affected FileBrowser instances.

## Attack Chain

1. An administrator configures a FileBrowser instance with `Signup=true` and `CreateUserDir=true`, allowing new users to self-register and automatically create their home directories.
2. A legitimate user registers an account (e.g., `teamone-x`), and FileBrowser creates a unique home directory for them (e.g., `/srv/users/teamone-x`).
3. An attacker registers a new account using a distinct username (e.g., `teamone/x`) that, after being processed by FileBrowser's `cleanUsername()` function, normalizes to the *same* home directory path (`/srv/users/teamone-x`).
4. The attacker logs in using their newly created colliding account.
5. The legitimate victim user creates or uploads sensitive files into their home directory (e.g., `secretA.txt`).
6. The attacker, logged in with their colliding account, sends a request to read `secretA.txt` via the FileBrowser API and successfully retrieves the victim's confidential data.
7. The attacker sends a request to overwrite `secretA.txt` with malicious or tampered content via the FileBrowser API.
8. The legitimate victim user subsequently accesses `secretA.txt` and observes the tampered content, unaware that their data has been compromised.

## Impact

This vulnerability leads to several critical impacts if exploited. An attacker registering a colliding username can achieve cross-user read access, allowing them to view every file within a victim's home directory. Furthermore, the attacker gains cross-user write and tamper capabilities, enabling them to overwrite, rename, or delete the victim's files, with the victim transparently seeing the tampered content. This directly bypasses the per-user isolation mechanism designed to confine each self-registered user to their designated scope. The attack can be targeted against known usernames or opportunistic. The precondition for exploitation is that the FileBrowser administrator must have both `Signup` and `CreateUserDir` settings enabled.

## Recommendation

* Patch FileBrowser instances to a version greater than 2.63.16 to address CVE-2026-62685 immediately.
* If immediate patching is not possible, disable the `Signup` and `CreateUserDir` settings in FileBrowser to mitigate the attack vector.
* Implement checks to ensure the derived scope for user directories is canonical and unique, as suggested by the recommended fix for CVE-2026-62685.
