---
title: Sudo Privilege Escalation Vulnerability (CVE-2026-35535)
slug: 2026-04-sudo-privesc
description: CVE-2026-35535 describes a privilege escalation vulnerability in Sudo versions up to 1.9.17p2, where a non-fatal error during privilege dropping can allow an attacker to gain elevated privileges.
date: "2026-04-03T03:16:18Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sudo
  - privilege-escalation
  - cve-2026-35535
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35535
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35535
  - https://bugs.debian.org/1130593
  - https://bugs.launchpad.net/ubuntu/+source/sudo/+bug/2143042
  - https://github.com/sudo-project/sudo/commit/3e474c2f201484be83d994ae10a4e20e8c81bb69
  - https://www.qualys.com/2026/03/10/crack-armor.txt
rules:
  - title: Detect Failed setuid/setgid/setgroups Calls by Sudo
    description: Detects error messages in system logs indicating a failure of setuid, setgid, or setgroups calls by the Sudo process, which is indicative of CVE-2026-35535 exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - system
      - linux
  - title: Detect Sudo Version vulnerable to CVE-2026-35535
    description: Detects when a vulnerable version of sudo is executed.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-35535 identifies a critical vulnerability within Sudo, specifically affecting versions up to 1.9.17p2 before commit 3e474c2. The vulnerability stems from a failure to properly handle errors during the privilege dropping process that occurs before running the mailer component. Specifically, if the setuid, setgid, or setgroups calls fail during this stage, the error is not treated as fatal. This flaw allows a malicious actor with limited privileges to potentially escalate their privileges to root or another privileged user. This vulnerability was reported in March 2026 and impacts systems relying on Sudo for privilege management, posing a significant risk to system integrity and confidentiality. Systems using affected versions of Sudo should be patched immediately to prevent potential exploitation.

## Attack Chain

1.  Attacker gains initial access to the system with a low-privileged account.
2.  Attacker identifies a vulnerable Sudo version (<= 1.9.17p2).
3.  Attacker crafts a malicious command intended to be executed via Sudo, specifically targeting the mailer functionality.
4.  Sudo attempts to drop privileges using setuid, setgid, or setgroups before executing the mailer.
5.  One of the privilege dropping calls (setuid, setgid, or setgroups) fails.
6.  Due to the vulnerability, the failure is not treated as a fatal error, and Sudo continues execution with incomplete privilege dropping.
7.  The mailer component executes with higher privileges than intended, as the privilege dropping was unsuccessful.
8.  Attacker leverages the elevated privileges to execute arbitrary commands or modify system files, gaining full control of the system.

## Impact

Successful exploitation of CVE-2026-35535 can lead to complete system compromise. An attacker can gain root privileges, allowing them to install malware, exfiltrate sensitive data, or disrupt critical services. The vulnerability affects any system using a vulnerable version of Sudo, potentially impacting a wide range of organizations and individuals. The severity is high because it allows for unauthenticated privilege escalation on systems where the vulnerable version of Sudo is installed and improperly configured.

## Recommendation

*   Upgrade Sudo to a patched version (>= 3e474c2) to remediate CVE-2026-35535.
*   Monitor system logs for failed setuid, setgid, or setgroups calls related to Sudo (see example Sigma rule below).
*   Implement stricter privilege management policies to minimize the impact of potential privilege escalation vulnerabilities.
