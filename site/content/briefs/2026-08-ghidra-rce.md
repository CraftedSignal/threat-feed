---
title: Arbitrary Code Execution in Ghidra Swift Demangler
slug: 2026-08-ghidra-rce
description: An arbitrary code execution vulnerability in the Ghidra Swift demangler analyzer allows attackers to execute arbitrary binaries by manipulating the Swift tool directory path within a project file.
date: "2026-08-03T18:06:17Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - National Security Agency
products:
  - Ghidra
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The SwiftNativeDemangler executes the resolved binary without integrity or signature verification, causing attacker-controlled executables to run under the Ghidra process user.
    confidence_band: high
cves:
  - id: CVE-2026-18718
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18718
action_plan:
  priority: elevated
  owners:
    - Security Operations
    - IT Operations
  immediate_actions:
    - action: Distribute a security alert to all internal security research teams to only open trusted Ghidra project files.
      owner: Security Operations
      due: 24h
      evidence: CVE-2026-18718 RCE vulnerability impact.
  mitigation_plan:
    - priority: immediate
      action: Patch or update Ghidra to the latest version provided by the vendor once available.
      owner: IT Operations
      addresses: CVE-2026-18718
      evidence: NVD vulnerability disclosure.
---

CVE-2026-18718 describes a critical arbitrary code execution vulnerability in the Swift demangler analyzer within the Ghidra reverse engineering framework. The vulnerability exists because the SwiftNativeDemangler component improperly handles path resolution for the Swift tool directory. When a user opens a project file, the SwiftDemanglerAnalyzer restores a persisted Swift binary directory path from the project state. Subsequently, the application executes a binary from the specified path without performing any integrity or signature validation. An attacker can craft a malicious Ghidra project file containing a path to a malicious executable. Upon opening the file, the executable runs under the context of the current Ghidra process user. This issue poses a significant risk to reverse engineering teams who frequently share and import third-party projects from untrusted sources, as the execution occurs without any warning or prompt to the user.

## Impact

Successful exploitation allows local arbitrary code execution under the privileges of the user running Ghidra. This could lead to full system compromise, exfiltration of sensitive reverse engineering data, or lateral movement within a developer's workstation environment. The scope of impact is limited to users who open malicious project files, but given the collaborative nature of security research, the distribution of compromised project files represents a high-risk vector for the research community.

## Recommendation

- Advise all users to avoid opening Ghidra projects received from untrusted or unverified third-party sources.
- Implement workstation-level restrictions to prevent Ghidra from executing binaries from temporary directories or user-writable locations.
- Review the official National Security Agency Ghidra security advisories for the release of a patched version.
- Monitor for unusual child processes spawned by the Ghidra process (ghidraRun or related binaries) using endpoint detection tools.
