---
title: 'CVE-2026-4802: Cockpit Command Injection Vulnerability'
slug: 2026-05-cockpit-rce
description: CVE-2026-4802 is a command injection vulnerability in Cockpit's system logs UI that allows a remote attacker to execute arbitrary commands on the host by exploiting unsanitized user-controlled parameters in crafted links.
date: "2026-05-11T14:17:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command injection
  - rce
  - web application
vendors:
  - Red Hat
products:
  - Cockpit
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-4802
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4802
  - https://access.redhat.com/security/cve/CVE-2026-4802
  - https://bugzilla.redhat.com/show_bug.cgi?id=2451155
  - https://github.com/cockpit-project/cockpit/blob/e204cd130/pkg/systemd/logsJournal.jsx#L206-L210
rules:
  - title: Detect CVE-2026-4802 Exploitation Attempt via Crafted URL
    description: Detects CVE-2026-4802 exploitation — Attempts to inject shell metacharacters into Cockpit system logs UI via crafted URLs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-4802 Exploitation Attempt via Systemd LogsJournal.jsx
    description: Detects CVE-2026-4802 exploitation — Identifies requests to the Systemd LogsJournal.jsx with suspicious characters indicative of command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-4802 is a command injection vulnerability affecting Cockpit, a web-based interface for system administration. The vulnerability stems from the system logs UI, where user-controlled parameters within crafted links are not properly sanitized. An attacker can exploit this flaw by injecting shell metacharacters and command substitutions into these parameters, leading to the execution of arbitrary shell commands on the affected system. Successful exploitation can result in a complete system compromise, allowing the attacker to gain full control of the targeted machine. This vulnerability poses a significant risk to systems utilizing Cockpit for remote administration.

## Attack Chain

1.  The attacker crafts a malicious link containing shell metacharacters and command substitutions within user-controlled parameters.
2.  The attacker delivers the crafted link to a user with access to the Cockpit system logs UI, possibly through phishing or social engineering.
3.  The user clicks on the malicious link, which is processed by the Cockpit system logs UI.
4.  The Cockpit application fails to properly sanitize the user-controlled parameters within the link.
5.  The unsanitized parameters are passed to a system command.
6.  The injected shell metacharacters and command substitutions are interpreted by the shell.
7.  Arbitrary shell commands are executed on the host system with the privileges of the Cockpit process.
8.  The attacker gains control of the system and can perform actions such as installing malware, exfiltrating data, or disrupting services.

## Impact

Successful exploitation of CVE-2026-4802 allows a remote attacker to achieve arbitrary command execution on the host system. This can lead to a complete system compromise, potentially affecting all data and services hosted on the system. The lack of sanitization can allow an attacker to perform any action that the compromised Cockpit instance can, including installing malicious software, creating new user accounts, or accessing sensitive data.

## Recommendation

*   Apply available patches for Cockpit from Red Hat to remediate CVE-2026-4802.
*   Deploy the Sigma rule "Detect CVE-2026-4802 Exploitation Attempt via Crafted URL" to identify potential exploitation attempts in webserver logs.
*   Implement strict input validation and sanitization for all user-supplied parameters within Cockpit's system logs UI.
*   Regularly review and audit Cockpit logs for suspicious activity or unauthorized access.
