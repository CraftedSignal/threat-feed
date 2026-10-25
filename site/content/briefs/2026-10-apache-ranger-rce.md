---
brief_id: brief-2026-10-25-apache-ranger-rce
event_id: brief-2026-10-25-apache-ranger-rce
revision: 1
activity_at: "2026-10-25T08:40:53Z"
title: 'Apache Ranger: OS command injection in UnixUserGroupBuilder (CVE-2026-28672)'
slug: 2026-10-apache-ranger-rce
description: Apache Ranger versions 2.8.0 and earlier are vulnerable to OS command injection via the UnixUserGroupBuilder component when processing crafted usernames containing shell metacharacters.
date: "2026-10-25T08:40:53Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified through provided code snippets
cpes:
  - cpe:2.3:a:apache:ranger:*:*:*:*:*:*:*:*
tags:
  - apache
  - ranger
  - command-injection
  - cve-2026-28672
vendors:
  - Apache
products:
  - Ranger (<= 2.8.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: The UnixUserGroupBuilder runs the id command through a shell, concatenating the username into the command line.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OS command injection in Apache Ranger <= 2.8.0 UnixUserGroupBuilder via crafted username.
    confidence_band: high
cves:
  - id: CVE-2026-28672
    cvss: 9.8
    epss: 0.02631
    kev_status: "false"
references:
  - https://lists.apache.org/thread/CVE-2026-28672
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-28672
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-28672&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-28672 Exploitation - Suspicious Child Processes from Ranger
    description: Detects suspicious processes spawned by the Apache Ranger user-sync process, which indicates potential command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Apache Ranger to 2.9.0
      owner: IT Operations
      due: 24h
      evidence: Fixed Version listed as 2.9.0
  hunt_leads:
    - lead: Audit Ranger user-sync logs for usernames containing shell metacharacters
      technique_id: T1059.004
      data_needed:
        - Application logs (Ranger user-sync module)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The username comes from the configured user-sync source
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2.9.0
      owner: IT Operations
      addresses: CVE-2026-28672
      evidence: Apache Ranger 2.9.0 runs id directly as an argument vector
---

Apache Ranger versions 2.8.0 and earlier contain an OS command injection vulnerability (CVE-2026-28672) within the `UnixUserGroupBuilder` component of the user-sync (`unixusersync`) module. The vulnerability occurs because the application concatenates a username directly into a `bash -c` command string used to query group information. An attacker who can influence the synchronized username (e.g., via LDAP, Active Directory, or file-based sync sources) can inject shell metacharacters to execute arbitrary commands with the privileges of the Ranger user-sync process.

## Attack Chain

1. Attacker identifies an accessible user-sync source (LDAP, AD, or file) that Apache Ranger monitors.
2. Attacker injects a malicious username containing shell metacharacters (e.g., `username; command`) into the user-sync source.
3. The `UnixUserGroupBuilder` component fetches the malicious username from the source.
4. The application constructs a command string: `id -G [malicious_username]`.
5. The application executes the string via `Runtime.getRuntime().exec(new String[]{"bash", "-c", ...})`.
6. The shell interprets the metacharacters and executes the attacker-supplied command.

## Impact

Successful exploitation allows for arbitrary command execution on the host system running the Apache Ranger user-sync service, typically resulting in full compromise of the user-sync host.

## Recommendation

1. Upgrade Apache Ranger to version 2.9.0 or later, which executes the `id` command directly as an argument vector, preventing shell interpretation of the username.
2. Audit user-sync sources (LDAP/AD/File) for suspicious or unexpected usernames containing shell metacharacters (e.g., `;`, `&`, `|`, `` ` ``, `$`).
3. Monitor the user-sync host for spawned child processes originating from the Ranger Java process that are not expected administrative tools (e.g., `id`).
