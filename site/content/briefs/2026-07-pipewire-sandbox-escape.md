---
title: PipeWire Vulnerability CVE-2026-5674 Allows Sandbox Escape and Arbitrary Code Execution
slug: 2026-07-pipewire-sandbox-escape
description: A critical vulnerability, CVE-2026-5674, exists in PipeWire, a multimedia server, enabling an attacker to escape sandboxed applications like Flatpak by exploiting its PulseAudio compatibility layer to load a malicious library, leading to arbitrary code execution outside the sandbox and potential system compromise.
date: "2026-07-16T14:20:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sandbox-escape
  - privilege-escalation
  - arbitrary-code-execution
  - pipewire
  - linux
  - flatpak
vendors:
  - Red Hat
products:
  - PipeWire
  - Red Hat Enterprise Linux 10
  - Red Hat Enterprise Linux 9
affected_os:
  - Red Hat Enterprise Linux 10
  - Red Hat Enterprise Linux 9
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: An attacker with minimal permissions within a sandboxed environment can load a malicious library, leading to arbitrary code execution outside the sandbox
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: An attacker with minimal permissions within a sandboxed environment can load a malicious library, leading to arbitrary code execution outside the sandbox and potential compromise of the user's system.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Defenses
    evidence: This vulnerability allows an attacker to escape sandboxed applications, such as Flatpak, ... leading to arbitrary code execution outside the sandbox and potential compromise of the user's system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: leading to arbitrary code execution outside the sandbox and potential compromise of the user's system.
    confidence_band: high
cves:
  - id: CVE-2026-5674
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5674
  - https://access.redhat.com/security/cve/CVE-2026-5674
  - https://bugzilla.redhat.com/show_bug.cgi?id=2455341
---

A significant vulnerability, identified as CVE-2026-5674, has been discovered in PipeWire, the multimedia server commonly used in Linux distributions. This flaw, categorized as an "Uncontrolled Search Path Element" (CWE-427), specifically impacts PipeWire's PulseAudio compatibility layer. Attackers with even minimal permissions within a sandboxed application, such as Flatpak, can leverage this vulnerability. By manipulating the environment to load a malicious library, they can achieve arbitrary code execution outside the security confines of the sandbox. This bypass of application sandboxing leads to a direct privilege escalation and potential full compromise of the underlying operating system. The vulnerability affects PipeWire versions distributed with Red Hat Enterprise Linux 9 and 10, highlighting a critical risk for users relying on containerization for security.

## Attack Chain

1. An attacker gains initial, minimal privileges within a sandboxed application (e.g., Flatpak) running on a Linux system utilizing PipeWire.
2. The attacker identifies and targets the PipeWire multimedia server, specifically its PulseAudio compatibility layer.
3. The attacker exploits the "Uncontrolled Search Path Element" (CWE-427) vulnerability within PipeWire.
4. Through this exploit, the attacker manipulates the system's search path or environment to coerce PipeWire into loading a crafted, malicious library.
5. The malicious library executes outside the boundaries of the sandboxed application, effectively achieving a sandbox escape.
6. The executed malicious code runs with elevated privileges, leading to arbitrary code execution on the host system.
7. The attacker gains full compromise of the user's system, allowing for data exfiltration, further lateral movement, or installation of persistent malware.

## Impact

The successful exploitation of CVE-2026-5674 allows an attacker to completely bypass sandboxing mechanisms, such as those provided by Flatpak, which are designed to isolate applications and protect the host system. This leads directly to arbitrary code execution with the privileges of the PipeWire service or the user, escalating from a constrained sandboxed environment to full system control. Victims primarily include users of Linux distributions running PipeWire, especially Red Hat Enterprise Linux 9 and 10, where the affected PipeWire packages are deployed. The compromise can result in sensitive data theft, installation of backdoors, further network infiltration, or complete loss of system integrity.

## Recommendation

* Patch CVE-2026-5674 on all affected Red Hat Enterprise Linux 9 and 10 systems immediately by updating PipeWire packages via official Red Hat channels.
* Monitor for unusual library loads or process activity originating from sandboxed applications, as described in the Attack Chain, that attempt to interact with system services outside their intended scope.
* Ensure that Flatpak and other containerization technologies are kept up-to-date to benefit from any additional hardening or mitigations not directly related to this CVE.
