---
title: Local Privilege Escalation Chain on SUSE Linux via CVE-2025-6018 and CVE-2025-6019
slug: 2026-08-suse-lpe-chain
description: An exploit chain targeting SUSE Linux systems leverages CVE-2025-6018 and CVE-2025-6019 to achieve local privilege escalation to root by abusing PAM environment injection and a race condition in UDisks2.
date: "2026-08-26T09:03:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:suse:pam-config:1.1.8-24.71.1:*:*:*:*:*:*:*
vendors:
  - SUSE
products:
  - pam-config
  - pam_env.so
  - UDisks2
  - libblockdev
affected_os:
  - SUSE Linux
  - openSUSE
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Cette exploit enchaîne CVE-2025-6018 et CVE-2025-6019 pour réaliser une élévation de privilèges locale d’un utilisateur non privilégié à root.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.001
    technique_name: 'Abuse Elevation Control Mechanism: Setuid and Setgid'
    evidence: libblockdev monte automatiquement le système de fichiers pour effectuer le redimensionnement... laissant le bash SUID accessible... pour obtenir un shell root.
    confidence_band: high
cves:
  - id: CVE-2025-6018
    cvss: 7.8
    epss: 0.01018
  - id: CVE-2025-6019
    cvss: 7
    epss: 0.00461
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0RIONCOLLECTOR-EXPLOIT-CHAIN-CVE-2025-6018-6019
  - https://cdn2.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch SUSE systems against CVE-2025-6018 and CVE-2025-6019
      owner: IT Operations
      due: 48h
      evidence: Exploit chain is publicly available and poses a high risk of privilege escalation.
  hunt_leads:
    - lead: Search for the existence of ~/.pam_environment files on critical SUSE servers.
      technique_id: T1548.001
      data_needed:
        - File system auditing
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit chain creates this file to perform PAM environment injection.
---

Publicly available proof-of-concept exploits describe a multi-stage local privilege escalation (LPE) chain targeting SUSE and openSUSE distributions. The attack leverages CVE-2025-6018 and CVE-2025-6019 to elevate an unprivileged user to root. The first stage involves exploiting an environment variable injection vulnerability in the PAM module `pam_env.so` (CVE-2025-6018). By injecting specific directives into `~/.pam_environment`, an attacker can manipulate XDG session variables to deceive `systemd-logind` into incorrectly granting 'allow_active' PolicyKit privileges.

Once the attacker gains these elevated permissions, they exploit a race condition in UDisks2 and `libblockdev` (CVE-2025-6019). This vulnerability occurs during the `Filesystem.Resize` D-Bus method call, where an attacker can mount a malicious XFS filesystem image containing a SUID root binary. Because the system fails to unmount the filesystem properly after a triggered error, the SUID binary becomes accessible in a temporary directory, allowing the attacker to execute it and obtain a root shell.

## Attack Chain

1. Attacker prepares a 300MB XFS filesystem image containing a SUID root bash binary on a local system.
2. Attacker transfers the malicious filesystem image to the target SUSE system, typically placing it in `/tmp/`.
3. Attacker modifies the local `~/.pam_environment` file on the target to include malicious XDG session variables (e.g., XDG_SEAT, XDG_VTNR).
4. Attacker triggers the PAM injection by logging out and logging back into the target system via SSH.
5. The target's `systemd-logind` processes the malicious environment, elevating the attacker's session status to 'allow_active' within PolicyKit.
6. Attacker initiates the `Filesystem.Resize` method via D-Bus, targeting the previously uploaded XFS image.
7. The `libblockdev` component mounts the image but fails to unmount it after the resize operation errors out, leaving the files accessible in `/tmp/blockdev*/`.
8. Attacker executes the SUID root bash binary found in the temporary mount point to gain root privileges.

## Impact

Successful exploitation results in full local privilege escalation, granting an attacker root access on affected SUSE and openSUSE systems. This allows for total system compromise, data exfiltration, and persistence, provided the attacker has already obtained an initial unprivileged user session.

## Recommendation

* Prioritize patching SUSE and openSUSE systems by applying official updates that address CVE-2025-6018 and CVE-2025-6019.
* Monitor systems for suspicious creation of `~/.pam_environment` files, particularly those containing XDG variable overrides.
* Audit PolicyKit configuration and limit 'allow_active' permissions for standard, non-interactive service accounts.
* Use File Integrity Monitoring (FIM) to detect the presence of SUID binaries in temporary directories like `/tmp/`.
