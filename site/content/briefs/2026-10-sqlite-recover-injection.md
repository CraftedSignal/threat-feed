---
brief_id: brief-2026-10-30-sqlite-recover-injection
event_id: brief-2026-10-30-sqlite-recover-injection
revision: 1
activity_at: "2026-10-30T13:30:02Z"
title: 'SQLite: Command injection in .recover command (CVE-2026-119586)'
slug: 2026-10-sqlite-recover-injection
description: The SQLite command-line shell through version 3.54.1 is vulnerable to command injection because the .recover command emits malicious dot-commands stored in the database schema, which execute when the output is piped back into the shell.
date: "2026-10-30T13:30:02Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*
tags:
  - sqlite
  - command-injection
  - vulnerability
vendors:
  - SQLite
products:
  - SQLite command-line shell (<= 3.54.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: Attackers can craft a database whose schema holds a valid CREATE statement followed by a .shell or .system line, executing OS commands when victims pipe .recover output into sqlite3.
    confidence_band: high
cves:
  - id: CVE-2026-119586
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119586
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  hunt_leads:
    - lead: Search for instances of the sqlite3 binary being invoked with the .recover command, particularly when paired with shell redirection or piping.
      technique_id: T1059
      data_needed:
        - Process creation logs (command line arguments)
        - Shell history logs (e.g., .bash_history, PowerShell history)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can craft a database whose schema holds a valid CREATE statement followed by a .shell or .system line, executing OS commands when victims pipe .recover output into sqlite3.
  mitigation_plan:
    - priority: immediate
      action: Upgrade SQLite command-line shell to a version after 3.54.1 once available
      owner: IT Operations
      addresses: CVE-2026-119586
      evidence: SQLite command-line shell through 3.54.1 contains a command injection vulnerability
---

SQLite command-line shell versions up to and including 3.54.1 contain a command injection vulnerability in the .recover functionality. When a database contains a specially crafted 'sqlite_schema' table entry, the .recover command includes attacker-controlled dot-commands (e.g., .shell or .system) in its output. If a victim executes the .recover command and redirects or pipes the resulting output into an active SQLite shell session, the injected system commands will execute with the privileges of the user running the shell.

## Attack Chain

1. Attacker creates a malicious database file containing a crafted sqlite_schema entry.
2. Attacker injects a malicious dot-command (e.g., .shell id) into the schema metadata.
3. Attacker lures or forces a victim to run the SQLite shell and execute the .recover command on the malicious database.
4. The .recover command outputs the attacker's malicious dot-commands to standard output.
5. The victim pipes this output into a new or existing sqlite3 process.
6. The sqlite3 shell interprets the piped input, parses the dot-commands, and executes the malicious OS command.

## Recommendation

1. Identify and inventory all systems utilizing the SQLite command-line shell (sqlite3) through version 3.54.1.
2. Update all instances of the SQLite command-line shell to a version beyond 3.54.1 as soon as a patch becomes available.
3. Implement strict controls over the execution of the .recover command on untrusted or externally sourced database files.
4. Use the hunt lead below to identify potential usage of the .recover command in automated pipelines where redirection may occur.
