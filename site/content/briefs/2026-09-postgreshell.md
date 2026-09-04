---
title: CVE-2026-6471 PostGREShell PostgreSQL Replication Vulnerability
slug: 2026-09-postgreshell
description: CVE-2026-6471, dubbed PostGREShell, allows attackers with Replication privileges to achieve remote code execution and escalate to superuser by abusing the logical decoding plugin loader.
date: "2026-09-04T13:06:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - privilege-escalation
  - database
vendors:
  - PostgreSQL
products:
  - PostgreSQL (9.4 - 18.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The plugin calls an internal function to become the bootstrap superuser for the session, then writes directly to pg_authid.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The plugin can also deploy backdoor mechanisms... and registers itself to be re-loaded into every new backend.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: This allows an attacker to load and execute any file through dlopen().
    confidence_band: high
cves:
  - id: CVE-2026-6471
    cvss: 7.2
    epss: 0.00285
references:
  - https://www.securityweek.com/12-year-old-postgresql-vulnerability-enables-database-server-takeover/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - DBA Team
  immediate_actions:
    - action: Upgrade PostgreSQL to the fixed versions (18.6, 17.11, 16.15, 15.19, 14.24)
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-6471 patch release data
  mitigation_plan:
    - priority: immediate
      action: Remove Replication attribute from unauthorized database accounts
      owner: DBA Team
      addresses: CVE-2026-6471
      evidence: Source advisory
---

CVE-2026-6471, known as PostGREShell, is a critical vulnerability affecting PostgreSQL versions 9.4 through 18.2. The vulnerability resides in the database's logical decoding mechanism, which allows external tools to read database events via replication slots and output plugins. An attacker with 'Replication' privileges can provide an arbitrary, unvalidated filesystem path to the plugin loader. Because the PostgreSQL plugin loader fails to sanitize the plugin name before passing it to the dlopen() function, an attacker can force the database to execute arbitrary shared libraries. This code runs with the privileges of the postgres system user, bypassing intended directory restrictions for non-superuser accounts. Once executed, the malicious code can gain full superuser privileges, modify the pg_authid catalog table, and establish persistent backdoors, such as passwordless access or automatic re-injection of the malicious payload. Given that logical replication is a standard feature for backups and monitoring, the attack surface is significant across production environments.

## Attack Chain

1. The attacker gains access to a credential with 'Replication' privileges, commonly provided to backup or monitoring utilities.
2. The attacker connects to the target PostgreSQL instance using the replication protocol.
3. The attacker creates a logical replication slot and specifies a malicious path or library file as the output plugin name.
4. The PostgreSQL server processes the malicious plugin name, failing to validate the path, and passes it to the dlopen() C function.
5. The attacker-controlled library file is loaded into the server process address space and executed as the postgres system user.
6. The executed code invokes internal PostgreSQL functions to elevate the current session to 'bootstrap superuser' status.
7. The attacker modifies the pg_authid system catalog table to assign permanent superuser flags to their account.
8. The attacker deploys a persistent backdoor by registering the malicious plugin to be re-loaded on new sessions or by modifying authentication settings for passwordless access.

## Impact

Successful exploitation allows for full database takeover, including the ability to read private data, modify all tables, read configuration files, and execute arbitrary operating system commands. This impacts any enterprise organization utilizing PostgreSQL for mission-critical databases where 'Replication' privileges are distributed to external tools. The attacker achieves persistence, potentially remaining undetected while exfiltrating data or using the database server as a pivot point in the internal network.

## Recommendation

1. Upgrade all PostgreSQL instances to the patched versions immediately: 18.6, 17.11, 16.15, 15.19, or 14.24.
2. Audit all accounts currently holding the 'Replication' attribute and remove it from any account or utility that does not strictly require it for replication or backup operations.
3. Implement strict filesystem access controls for the user account running the PostgreSQL service to limit the files accessible to the dlopen() function.
4. Monitor database logs for unusual logical replication slot creation events, particularly those referencing non-standard or unexpected plugin file paths.
