---
title: OCaml opam Path Traversal Vulnerability (CVE-2026-41082)
slug: 2026-04-opam-path-traversal
description: OCaml opam before 2.5.1 is vulnerable to path traversal via a crafted .install file, potentially allowing attackers to overwrite arbitrary files.
date: "2026-04-17T12:00:00Z"
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

OCaml opam, a package manager for OCaml, is susceptible to a path traversal vulnerability (CVE-2026-41082) in versions prior to 2.5.1. The vulnerability stems from insufficient validation of filepaths specified within the ".install" files used to define package installation procedures. Specifically, the ".install" field, which dictates the destination of installed files, permits the inclusion of "../" sequences. This oversight can be exploited by malicious package maintainers or compromised…
