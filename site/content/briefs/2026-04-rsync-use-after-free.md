---
title: rsync Use-After-Free Vulnerability in Extended Attribute Handling (CVE-2026-41035)
slug: 2026-04-rsync-use-after-free
description: rsync versions 3.0.1 through 3.4.1 are vulnerable to a use-after-free vulnerability in the receive_xattr function during a qsort call, triggered by an untrusted length value when the -X/--xattrs option is used, potentially leading to code execution.
date: "2026-04-16T07:16:31Z"
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

rsync versions 3.0.1 through 3.4.1 are susceptible to a use-after-free vulnerability identified as CVE-2026-41035. This flaw resides within the `receive_xattr` function, where an untrusted length value is used during a `qsort` call. The vulnerability is triggered only when rsync is executed with the `-X` or `--xattrs` option, which enables extended attribute handling. While many Linux configurations are vulnerable, the issue is more prevalent on non-Linux platforms. Exploitation of this…
