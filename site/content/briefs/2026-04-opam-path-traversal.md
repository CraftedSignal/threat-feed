---
title: OCaml opam Path Traversal Vulnerability (CVE-2026-41082)
slug: 2026-04-opam-path-traversal
description: OCaml opam before 2.5.1 is vulnerable to path traversal via a crafted .install file, potentially allowing attackers to overwrite arbitrary files.
date: "2026-04-17T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - package-manager
  - ocaml
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-41082
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41082
  - https://github.com/ocaml/opam/pull/6897
  - https://github.com/ocaml/opam/releases/tag/2.5.1
rules:
  - title: Detect Opam Path Traversal in Install Files
    description: Detects attempts to exploit path traversal vulnerabilities in opam .install files by identifying suspicious file paths containing '../'.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - file_event
      - linux
  - title: Detect Opam Install Command with Suspicious Arguments
    description: Detects opam install commands that may be attempting to exploit path traversal vulnerabilities by including suspicious characters.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OCaml opam, a package manager for OCaml, is susceptible to a path traversal vulnerability (CVE-2026-41082) in versions prior to 2.5.1. The vulnerability stems from insufficient validation of filepaths specified within the ".install" files used to define package installation procedures. Specifically, the ".install" field, which dictates the destination of installed files, permits the inclusion of "../" sequences. This oversight can be exploited by malicious package maintainers or compromised repositories to overwrite files outside the intended installation directory. This allows attackers to manipulate critical system files, potentially escalating privileges and compromising the entire system. The impact is significant for developers and systems relying on opam for package management, as it introduces a risk of arbitrary file modification and subsequent system compromise.

## Attack Chain

1. An attacker crafts a malicious OCaml package containing a specially crafted ".install" file.
2. The malicious ".install" file contains a destination filepath that utilizes "../" sequences to traverse to parent directories.
3. A user unknowingly installs the malicious package using `opam install <package>`.
4. Opam parses the ".install" file and executes the file installation instructions.
5. Due to the path traversal vulnerability, opam writes files to unintended locations outside of the intended package directory.
6. The attacker overwrites critical system files, such as configuration files or binaries.
7. The system is compromised as a result of the overwritten files, potentially leading to privilege escalation or arbitrary code execution.
8. The attacker gains control of the system.

## Impact

Successful exploitation of this vulnerability can lead to arbitrary file overwrite, potentially resulting in privilege escalation, code execution, and complete system compromise. While the specific number of affected systems is unknown, any system utilizing OCaml opam versions before 2.5.1 is potentially vulnerable. This includes development environments, build servers, and production systems relying on OCaml packages installed through opam. A successful attack could lead to data loss, system instability, or unauthorized access to sensitive information.

## Recommendation

*   Upgrade OCaml opam to version 2.5.1 or later to remediate CVE-2026-41082 (see references).
*   Deploy the Sigma rule `Detect Opam Path Traversal in Install Files` to detect attempts to exploit this vulnerability by monitoring for suspicious file paths during opam package installation.
*   Implement strict controls over the packages and repositories used by opam to prevent the installation of malicious or compromised packages.
*   Regularly audit the ".install" files of installed packages for suspicious path traversal sequences.
