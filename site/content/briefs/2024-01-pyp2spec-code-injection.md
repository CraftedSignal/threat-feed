---
title: pyp2spec Code Injection Vulnerability
slug: 2024-01-pyp2spec-code-injection
description: pyp2spec before 0.14.1 is vulnerable to code injection by writing PyPI package metadata into generated spec files without escaping RPM macro directives, allowing malicious packages to execute arbitrary commands on the build machine.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - supply-chain
  - rpm
  - linux
vendors:
  - pip
  - Fedora
products:
  - pyp2spec (< 0.14.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-r35x-v8p8-xvhw
rules:
  - title: Detect Suspicious Process Execution from RPMbuild
    description: Detects suspicious process executions originating from rpmbuild, potentially indicating code injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of RPM Spec Files
    description: Detects modifications to RPM spec files, which could indicate code injection or tampering.
    platform: sigma
    severity: medium
    tactics:
      - integrity
    techniques:
      - T1565.001
    data_sources:
      - file_event
      - linux
  - title: Detect RPM Macro Command Injection
    description: Detects execution of shell commands directly within RPM macro expansions, potentially indicating command injection
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

pyp2spec, a tool for generating RPM spec files from PyPI packages, contains a code injection vulnerability affecting versions prior to 0.14.1. The vulnerability stems from the tool's failure to properly escape RPM macro directives when writing PyPI package metadata (such as the summary field) into the generated spec file. This allows a malicious PyPI package to inject arbitrary commands into the spec file, which are then executed when an RPM tool processes the file. This poses a significant risk to package maintainers and build systems, particularly within the Fedora ecosystem where compromised credentials can lead to widespread supply chain attacks. The realistic attack vector involves typosquatting or targeting packages known to be under review.

## Attack Chain

1. An attacker crafts a malicious PyPI package containing specially formatted metadata, including an RPM macro directive (e.g., within the package summary).
2. A Fedora packager, intending to package a legitimate Python package, uses `pyp2spec` to generate an RPM spec file from the malicious PyPI package.
3. `pyp2spec` writes the attacker-controlled metadata, including the unescaped RPM macro directive, into the generated spec file.
4. The packager, or an automated system, uses an RPM tool like `rpmbuild -bs`, `rpmbuild --nobuild`, or `rpm -q --specfile` to inspect or build the package from the spec file.
5. The RPM tool parses the spec file and, upon encountering the RPM macro directive, executes the embedded command.
6. The attacker's command executes on the build machine, potentially granting the attacker access to the packager's credentials (dist-git SSH keys, Koji build credentials, Bodhi update credentials).
7. The attacker uses the compromised credentials to commit malicious source code to the distribution's Git repository (dist-git).
8. The malicious code is built and distributed to end users through the normal package update pipeline, resulting in a supply chain attack.

## Impact

Successful exploitation allows attackers to execute arbitrary commands on the build machine. This can lead to the compromise of sensitive credentials, such as SSH keys and build system credentials. In the Fedora ecosystem, this could enable an attacker to inject malicious code into packages that are distributed to end users, potentially affecting millions of systems. The vulnerability poses a high risk to package maintainers and build systems.

## Recommendation

*   Upgrade to `pyp2spec` version 0.14.1 or later to remediate the code injection vulnerability as described in the advisory (https://github.com/advisories/GHSA-r35x-v8p8-xvhw).
*   Implement file integrity monitoring on RPM spec files, alerting on unexpected modifications, to detect potentially malicious injected code. Use file_event logs with a rule like the one below.
*   Monitor process executions originating from RPM tools (`rpmbuild`, `rpm`), focusing on unusual or unexpected commands that could indicate exploitation, using process_creation logs and the Sigma rule provided.
