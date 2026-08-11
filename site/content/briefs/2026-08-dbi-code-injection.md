---
title: Code Injection Vulnerability in Perl DBI
slug: 2026-08-dbi-code-injection
description: An incomplete patch for CVE-2026-14380 introduced a code injection vulnerability (CWE-94) in the perl-DBI package for Red Hat Enterprise Linux 9 and 10, potentially allowing authenticated attackers to execute arbitrary code.
date: "2026-08-11T18:36:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:perl:dbi:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - rhel
vendors:
  - Red Hat
products:
  - Red Hat Enterprise Linux 9
  - Red Hat Enterprise Linux 10
  - perl-DBI
affected_os:
  - RHEL 9.8.z
  - RHEL 10.2.z
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A flaw was found in DBI. This is a fix for a partial fix for CVE-2026-14380 for RHEL 9.8.z and 10.2.z.
    confidence_band: high
cves:
  - id: CVE-2026-14380
    cvss: 8.8
    epss: 0.00479
references:
  - https://access.redhat.com/security/cve/CVE-2026-19546
  - https://bugzilla.redhat.com/show_bug.cgi?id=2513963
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19546
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Deploy vendor-supplied patches for perl-DBI for RHEL 9.8.z and 10.2.z.
      owner: IT Operations
      due: 48h
      evidence: High severity vulnerability identified in Red Hat official security advisory.
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate high-risk applications utilizing perl-DBI that accept untrusted user input.
      owner: Security Operations
      addresses: CVE-2026-19546
      evidence: Vulnerability allows code injection via the DBI interface.
---

A code injection vulnerability (CWE-94) has been identified in the `perl-DBI` package shipped with Red Hat Enterprise Linux (RHEL) versions 9 and 10. This security flaw stems from an incomplete remediation of the previously disclosed CVE-2026-14380. The vulnerability allows an authenticated attacker to perform code injection, which may result in remote code execution, unauthorized data access, or denial of service, depending on the specific application implementation leveraging the database interface. Red Hat has categorized this as a high-severity issue, specifically affecting RHEL 9.8.z and 10.2.z environments. Defenders should prioritize patching the `perl-DBI` package as updates become available via official channels.

## Impact

Successful exploitation of this flaw could allow an authenticated attacker to compromise the integrity, confidentiality, and availability of database-backed applications. Given the widespread use of Perl DBI for database connectivity, the potential scope of impact includes any service or administrative tool utilizing this library to execute database queries. As this is a flaw in a core language interface, the damage could involve full system compromise if the Perl scripts are running with elevated privileges.

## Recommendation

* Apply the security patches for `perl-DBI` issued by Red Hat for RHEL 9.8.z and 10.2.z immediately upon availability.
* Audit applications that utilize `perl-DBI` to identify where user-supplied input is passed to database interaction methods, as these are the likely entry points for exploitation.
* Monitor for unexpected child processes spawned by services or scripts that rely on the Perl DBI interface.
* Review Red Hat Bugzilla entry 2513963 for updates regarding specific remediation steps and version-specific patch releases.
