---
title: Radare2 Command Injection Vulnerability (CVE-2026-41015)
slug: 2026-04-radare2-cmd-injection
description: Radare2 before commit 9236f44, when configured on UNIX without SSL, is vulnerable to command injection via a PDB name passed to rabin2 -PP, potentially allowing arbitrary code execution.
date: "2026-04-16T03:16:27Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - radare2
  - command-injection
  - cve-2026-41015
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-41015
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41015
  - https://github.com/radareorg/radare2/commit/9236f44a28812fe911814e1b3a7bcf1e4de5d3c2
  - https://github.com/radareorg/radare2/blob/9236f44a28812fe911814e1b3a7bcf1e4de5d3c2/SECURITY.md?plain=1#L3-L5
  - https://github.com/radareorg/radare2/issues/25650
  - https://github.com/radareorg/radare2/pull/25651
rules:
  - title: Detect Suspicious rabin2 Execution
    description: Detects suspicious executions of rabin2, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Radare2 rabin2 PDB Injection
    description: Detects potential command injection attempts via PDB file names in rabin2.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-41015 is a command injection vulnerability affecting radare2, a reverse engineering framework, when configured on UNIX systems without SSL. The vulnerability occurs in the `rabin2` utility, specifically when processing Program Database (PDB) files with the `-PP` option. An attacker can inject arbitrary commands into the PDB name, which are then executed by the system. This vulnerability exists within a specific commit range after version 6.1.2 and before 6.1.3 (commit 9236f44). While radare2 encourages users to use the latest git version, the short timeframe of the vulnerable code increases the risk for users who have not updated within that period. Exploitation could lead to complete system compromise if the radare2 process has sufficient privileges.

## Attack Chain

1.  Attacker identifies a vulnerable radare2 installation configured on a UNIX system without SSL.
2.  Attacker crafts a malicious PDB file name containing embedded OS commands.
3.  Attacker supplies the crafted PDB file name as input to the `rabin2 -PP` command.
4.  `rabin2` processes the PDB name without proper sanitization.
5.  The embedded OS commands within the PDB name are executed by the system.
6.  Attacker gains arbitrary code execution within the context of the radare2 process.
7.  Attacker leverages the initial access to escalate privileges.
8.  Attacker performs malicious actions such as data exfiltration, system compromise, or denial of service.

## Impact

Successful exploitation of CVE-2026-41015 allows an attacker to execute arbitrary commands on the affected system. This can lead to complete system compromise, including data theft, malware installation, or denial of service. The impact is particularly severe if radare2 is running with elevated privileges. The number of potential victims is dependent on the number of radare2 installations running vulnerable versions and configurations, but it is estimated to be relatively low due to the specific configuration requirements and the short lifespan of the vulnerable code in the git repository.

## Recommendation

*   Apply the patch from commit 9236f44 to remediate the command injection vulnerability in radare2.
*   Avoid configuring radare2 on UNIX systems without SSL to reduce the attack surface.
*   Deploy the Sigma rule `radare2-suspicious-rabin2-execution` to detect exploitation attempts involving the `rabin2` command.
*   Monitor process execution for `rabin2` with unusual command-line arguments as indicated by the rule `radare2-rabin2-pdb-injection`.
