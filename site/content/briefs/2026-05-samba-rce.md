---
title: 'CVE-2026-4408: Samba Remote Command Execution via Misconfigured Password Check Script'
slug: 2026-05-samba-rce
description: CVE-2026-4408 describes a remote command execution vulnerability in Samba file servers and classic domain controllers where a misconfigured 'check password script' feature, using the %u substitution character without proper escaping, allows attackers to execute arbitrary commands.
date: "2026-05-28T09:19:01Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - rce
  - samba
vendors:
  - Samba
products:
  - Samba
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-4408
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4408
rules:
  - title: Detect CVE-2026-4408 Exploitation Attempt via Malicious Username
    description: Detects CVE-2026-4408 exploitation — Attempts to authenticate to Samba with a username containing shell meta-characters, indicating a potential command injection attempt via a misconfigured 'check password script'.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
    data_sources:
      - auth
      - samba
  - title: Detect CVE-2026-4408 Exploitation - Password Check Script Execution of Suspicious Commands
    description: Detects CVE-2026-4408 exploitation — Monitors process creation events for commands executed by the 'check password script' that contain suspicious shell metacharacters indicating command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-4408 describes a critical vulnerability affecting Samba file servers and classic domain controllers. The vulnerability stems from a misconfiguration in the "check password script" feature. When this script is configured to use the %u substitution character, the username supplied by the client is passed to the script without proper escaping of shell meta-characters. This allows a remote attacker to inject arbitrary commands that are then executed on the affected system. This vulnerability is most likely to be present in non-standard configurations where the "check password script" is used with %u and the samba-dcerpcd service is running as a system service. Defenders should review their Samba configurations to ensure they are not vulnerable.

## Attack Chain

1.  Attacker identifies a Samba server with the 'check password script' feature enabled and configured with the %u substitution character.
2.  Attacker crafts a malicious username containing shell meta-characters (e.g., `;`, `|`, `&`, `$()`).
3.  Attacker attempts to authenticate to the Samba server using the crafted username and an arbitrary password.
4.  The Samba server passes the crafted username, without proper escaping, to the configured 'check password script'.
5.  The 'check password script' executes the injected shell commands due to the presence of unescaped meta-characters in the username.
6.  The attacker achieves arbitrary command execution on the Samba server with the privileges of the user running the 'samba-dcerpcd' service.
7.  Attacker leverages the command execution to install a backdoor, escalate privileges, or perform other malicious activities.

## Impact

Successful exploitation of CVE-2026-4408 allows a remote attacker to execute arbitrary commands on the affected Samba server. This can lead to complete system compromise, data theft, denial of service, or further propagation within the network. The vulnerability affects Samba file servers and classic domain controllers, potentially impacting organizations relying on these services for file sharing and authentication. The CVSS v3.1 base score for this vulnerability is 9.0, indicating a critical severity.

## Recommendation

*   Review Samba configurations for the 'check password script' feature and the use of the %u substitution character as described in the overview.
*   Apply appropriate input validation and sanitization to user-supplied data passed to the 'check password script'.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect exploitation attempts targeting CVE-2026-4408.
