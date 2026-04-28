---
title: rsync Use-After-Free Vulnerability in Extended Attribute Handling (CVE-2026-41035)
slug: 2026-04-rsync-use-after-free
description: rsync versions 3.0.1 through 3.4.1 are vulnerable to a use-after-free vulnerability in the receive_xattr function during a qsort call, triggered by an untrusted length value when the -X/--xattrs option is used, potentially leading to code execution.
date: "2026-04-16T07:16:31Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - rsync
  - use-after-free
  - cve-2026-41035
  - linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41035
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41035
  - https://github.com/RsyncProject/rsync/issues/871
  - https://github.com/RsyncProject/rsync/releases
  - https://www.openwall.com/lists/oss-security/2026/04/16/2
rules:
  - title: Detect rsync with Extended Attributes Option
    description: Detects rsync commands using the -X or --xattrs option, which is necessary to trigger CVE-2026-41035
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect rsync Binary Modification
    description: Detects modification of the rsync binary, which could indicate an attempt to inject malicious code to exploit CVE-2026-41035
    platform: sigma
    severity: high
    tactics:
      - integrity
    techniques:
      - T1565.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

rsync versions 3.0.1 through 3.4.1 are susceptible to a use-after-free vulnerability identified as CVE-2026-41035. This flaw resides within the `receive_xattr` function, where an untrusted length value is used during a `qsort` call. The vulnerability is triggered only when rsync is executed with the `-X` or `--xattrs` option, which enables extended attribute handling. While many Linux configurations are vulnerable, the issue is more prevalent on non-Linux platforms. Exploitation of this vulnerability could allow a malicious actor to achieve arbitrary code execution on the target system. Defenders should prioritize patching rsync installations and consider disabling the `-X` option where extended attributes are not essential.

## Attack Chain

1.  Attacker gains initial access to a system where they can influence rsync parameters. This could be through a compromised user account or a vulnerable service.
2.  Attacker crafts a malicious rsync command that includes the `-X` or `--xattrs` option to enable extended attribute processing.
3.  The crafted command is executed on the victim machine, targeting a vulnerable rsync version (3.0.1 to 3.4.1).
4.  During the `receive_xattr` function call, the untrusted length value provided by the attacker is passed to the `qsort` function.
5.  The `qsort` function attempts to sort the extended attributes based on the attacker-controlled length.
6.  Due to the manipulated length value, the `qsort` function accesses memory outside the allocated buffer, leading to a use-after-free condition.
7.  The use-after-free condition allows the attacker to potentially overwrite memory with malicious code.
8.  The attacker's code is executed within the context of the rsync process, granting them control of the system.

## Impact

Successful exploitation of CVE-2026-41035 can lead to arbitrary code execution on the affected system. The impact can range from data corruption to complete system compromise. Given the widespread use of rsync for data synchronization and backups, a successful attack could affect a large number of systems across various sectors. The vulnerability is particularly concerning on non-Linux platforms, where the likelihood of successful exploitation is higher.

## Recommendation

*   Upgrade rsync to a version beyond 3.4.1 to patch CVE-2026-41035.
*   Implement the file integrity monitoring rule to detect unauthorized modification of rsync binaries.
*   Deploy the Sigma rule to detect rsync commands using the `-X` or `--xattrs` option, as those options are required to trigger this vulnerability.
*   Where possible, disable the use of the `-X` or `--xattrs` option for rsync to prevent exploitation of this vulnerability.
