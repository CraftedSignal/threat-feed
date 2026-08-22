---
title: 'CVE-2026-68766: Argument Injection in Hashcat Restore Files'
slug: 2026-08-hashcat-restore-injection
description: Hashcat is vulnerable to argument injection when parsing restore files, potentially leading to arbitrary code execution if a user restores a malicious session file.
date: "2026-08-22T15:31:53Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - hashcat
products:
  - hashcat
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft restore files with malicious options to append attacker-controlled content to arbitrary files, enabling code execution when targeting shell startup files.
    confidence_band: high
cves:
  - id: CVE-2026-68766
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68766
  - https://github.com/hashcat/hashcat/commit/fcae69f2438ff8eae0dc8e206b78067a1e465ed4
  - https://www.vulncheck.com/advisories/hashcat-through-arbitrary-file-write-via-restore-file-option-injection
rules:
  - title: Detect Potential Hashcat Argument Injection
    description: Detects hashcat being invoked with output redirection flags that correlate with the CVE-2026-68766 argument injection vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch hashcat instances to version > 7.1.2.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-68766 affects 7.1.2 and below.
  hunt_leads:
    - lead: Search for shell configuration files (e.g., .bashrc, .zshrc) recently modified by hashcat binaries.
      technique_id: T1059
      data_needed:
        - File integrity monitoring logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can target shell startup files via --outfile injection.
  mitigation_plan:
    - priority: immediate
      action: Upgrade hashcat.
      owner: IT Operations
      addresses: CVE-2026-68766
      evidence: Vendor fix available.
---

Hashcat versions up to and including 7.1.2 are susceptible to an argument injection vulnerability (CVE-2026-68766) occurring during the parsing of restore files. This flaw allows an attacker to inject arbitrary command-line options, such as --outfile or --potfile-path, by crafting a malicious restore file. When a user runs hashcat with this file, the application processes these injected options without sufficient validation. An attacker can leverage this to redirect hashcat output to arbitrary locations on the filesystem. By targeting shell startup files (such as .bashrc, .profile, or .zshrc), an attacker can append malicious commands to these files, leading to arbitrary code execution when the victim next opens a shell. This vulnerability relies on the user performing a restore action, making it a viable target for local attackers or those capable of dropping files in directories where a user typically runs password recovery operations.

## Attack Chain

1. Attacker creates a malicious session restore file with injected command-line arguments (e.g., --outfile).
2. Attacker places the crafted restore file in a directory monitored or used by a target user for hashcat sessions.
3. Victim executes hashcat, pointing to the malicious restore file (e.g., hashcat --restore session.restore).
4. Hashcat process parses the restore file and executes with the injected flags applied to its internal state.
5. Hashcat writes its output or potfile data to the path specified by the attacker (e.g., ~/.bashrc).
6. The injected payload is successfully appended to the target shell configuration file.
7. Victim starts a new shell session, triggering the execution of the appended commands.
8. Attacker-controlled code runs within the context of the user, achieving full arbitrary code execution.

## Impact

Successful exploitation results in arbitrary code execution within the security context of the victim user. This could lead to full system compromise, data theft, or persistence on the host. The vulnerability affects all platforms (Windows, Linux, macOS) where hashcat 7.1.2 or earlier is deployed.

## Recommendation

* Upgrade to the latest version of hashcat (post-7.1.2) where the parsing logic for restore files has been restricted.
* Audit hashcat session directories for unexpected restore file modifications, particularly in shared compute environments.
* Monitor for processes spawning with unexpected command-line arguments derived from file inputs.
* Deploy the Sigma rules below to detect suspicious hashcat command-line invocation patterns.
