---
title: Samba Print Spooler Remote Code Execution via CVE-2026-4480
slug: 2026-05-samba-rce
description: CVE-2026-4480 allows a remote attacker to achieve remote code execution on a vulnerable Samba server by sending a specially crafted print job description containing unescaped shell metacharacters, which are then passed to the configured 'print command'.
date: "2026-05-26T15:20:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-4480
  - rce
  - samba
  - command injection
vendors:
  - Red Hat
  - Samba
products:
  - Samba
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-4480
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4480
  - https://access.redhat.com/security/cve/CVE-2026-4480
  - https://bugzilla.redhat.com/show_bug.cgi?id=2452232
  - https://bugzilla.samba.org/show_bug.cgi?id=16033
rules:
  - title: Detect CVE-2026-4480 Exploitation Attempt via Print Job Name
    description: Detects CVE-2026-4480 exploitation — detects print job submissions containing shell metacharacters that could lead to command injection.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.002
    data_sources:
      - print
      - samba
  - title: Detect CVE-2026-4480 Exploitation via Suspicious Process Execution from Samba
    description: Detects CVE-2026-4480 exploitation — monitors for suspicious processes spawned by the Samba process after a print job submission.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-4480 is a critical vulnerability affecting the Samba printing subsystem. The flaw stems from the insecure handling of client-provided job descriptions. Specifically, Samba passes the client-controlled job description string to the command configured with the "print command" setting using the "%J" substitution character without properly escaping shell meta characters. An unauthenticated remote attacker can exploit this vulnerability by sending a malicious print job description containing unescaped shell characters, allowing for arbitrary command execution on the Samba server. This poses a significant risk to organizations relying on Samba for file and print services.

## Attack Chain

1.  The attacker sends a specially crafted print job to the Samba server.
2.  The print job description contains shell meta characters (e.g., `;`, `|`, `&&`) within the job name.
3.  Samba receives the print job and extracts the malicious job description.
4.  Samba substitutes the job description for the `%J` variable within the "print command" setting.
5.  The "print command" is executed by the Samba server, without proper sanitization or escaping of the shell meta characters.
6.  The injected shell commands in the job description are executed with the privileges of the Samba process.
7.  The attacker gains arbitrary code execution on the Samba server.
8.  The attacker can then perform post-exploitation activities such as lateral movement, data exfiltration, or system compromise.

## Impact

Successful exploitation of CVE-2026-4480 allows a remote, unauthenticated attacker to execute arbitrary code with elevated privileges on the affected Samba server. This could lead to a full system compromise, data theft, or denial of service. Given the widespread use of Samba in enterprise environments for file and print sharing, this vulnerability poses a significant risk, potentially affecting thousands of organizations.

## Recommendation

*   Review the "print command" setting in your Samba configuration (smb.conf) and ensure that no custom commands are used that could be vulnerable to command injection via the `%J` substitution character.
*   Deploy the Sigma rules provided below to your SIEM to detect potential exploitation attempts.
*   Apply available patches as provided by Red Hat and Samba to remediate CVE-2026-4480.
