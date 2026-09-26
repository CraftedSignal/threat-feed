---
title: Local Privilege Escalation in sudo via TZ Variable Manipulation
slug: 2026-09-sudo-time-bypass
description: A vulnerability in sudo (CVE-2026-96512) allows an authenticated local user to bypass time-based access restrictions by manipulating the TZ environment variable to influence timestamp evaluation.
date: "2026-09-26T00:35:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sudo_project:sudo:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - sudo
vendors:
  - Sudo Project
products:
  - sudo (1.8.20 - 1.9.17p2)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in sudo (CVE-2026-96512) allows an authenticated local user to bypass time-based access restrictions.
    confidence_band: high
cves:
  - id: CVE-2026-96512
    cvss: 7.8
    epss: 0.00132
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96512
  - http://www.openwall.com/lists/oss-security/2026/09/24/4
  - https://github.com/sudo-project/sudo/commit/1820a349687522f51023d1ae5925125f59679a8c
rules:
  - title: Detect Suspicious sudo Execution with TZ Environment Variable
    description: Detects the use of sudo with a manually defined TZ environment variable, which may indicate an attempt to exploit CVE-2026-96512.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit sudoers configuration files for NOTBEFORE/NOTAFTER rules lacking 'Z'.
      owner: IT Operations
      due: 48h
      evidence: Source advisory notes the lack of 'Z' causes the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade sudo to the build corresponding to commit 1820a34 or newer.
      owner: IT Operations
      addresses: CVE-2026-96512
      evidence: Patch remediation section in source.
---

A vulnerability (CVE-2026-96512) exists in sudo versions 1.8.20 through 1.9.17p2, affecting how the utility parses time-based access restrictions defined in the sudoers file. When NOTBEFORE or NOTAFTER rules are configured without the mandatory trailing 'Z' timezone indicator, the application uses the TZ environment variable inherited from the calling user's shell session to calculate the temporal validity of the command execution. 

An authenticated local user who is already permitted to run specific commands under time-based constraints can exploit this behavior by setting a custom TZ variable (e.g., UTC+14) to shift the evaluation window by up to 25 hours. This allows the attacker to execute privileged commands outside of the intended time window, potentially escalating to root privileges if the sudoers rule grants such access. The vulnerability requires local access and an existing sudoers policy that utilizes time-based restrictions without absolute UTC timestamps.

## Attack Chain

1. Attacker identifies a local account with sudo privileges restricted by NOTBEFORE or NOTAFTER clauses.
2. Attacker examines the sudoers configuration file (e.g., /etc/sudoers) to find time-based rules missing the 'Z' indicator.
3. Attacker determines the current restricted window defined in the sudoers policy.
4. Attacker crafts a command-line environment by defining a specific TZ environment variable to shift the local time relative to the restricted window.
5. Attacker executes the sudo command with the modified TZ environment variable: 'TZ=UTC+14 sudo -n [command]'.
6. The sudo binary's 'parse_gentime' function reads the injected TZ variable during 'mktime()' execution.
7. The epoch window shifts, causing the time evaluation to permit the command execution despite the actual time being outside the intended range.
8. Sudo grants authorization, allowing the attacker to execute the command with root privileges.

## Impact

Successful exploitation allows a local user to bypass administrative access controls, facilitating unauthorized execution of commands as root. This vulnerability affects systems using time-limited sudo access, potentially leading to full system compromise, data exfiltration, or persistence establishment. It is restricted to local authenticated users and does not provide remote network-based exploitation vectors.

## Recommendation

1. Upgrade sudo to the version containing the fix for commit 1820a34 or newer to ensure TZ environment variables are correctly handled or sanitized during timestamp parsing.
2. Audit all sudoers files for time-based access rules (NOTBEFORE/NOTAFTER) and ensure all time definitions include the 'Z' timezone indicator to force UTC evaluation regardless of user environment variables.
3. Deploy the Sigma rule below to monitor for suspicious TZ variable usage with sudo commands.
