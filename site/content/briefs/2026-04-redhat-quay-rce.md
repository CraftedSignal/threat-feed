---
title: Red Hat Quay Deserialization Vulnerability Leads to Remote Code Execution (CVE-2026-32590)
slug: 2026-04-redhat-quay-rce
description: CVE-2026-32590 describes a deserialization vulnerability in Red Hat Quay's handling of resumable container image layer uploads, potentially allowing an attacker to execute arbitrary code on the Quay server by tampering with intermediate data stored in the database.
date: "2026-04-08T18:25:59Z"
severities:
  - critical
tags:
  - cve-2026-32590
  - redhat-quay
  - deserialization
  - rce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-32590
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32590
  - https://access.redhat.com/security/cve/CVE-2026-32590
  - https://bugzilla.redhat.com/show_bug.cgi?id=2446964
rules:
  - title: Detect Quay Deserialization Attempt
    description: Detects potential exploitation attempts of the Red Hat Quay deserialization vulnerability (CVE-2026-32590) by monitoring for suspicious processes spawned by the Quay server.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
      - T1566.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Quay Database Tampering
    description: Detects potential database tampering related to CVE-2026-32590 by monitoring for unauthorized access attempts.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - database
      - linux
rules_count: 2
---

Red Hat Quay is vulnerable to a critical deserialization flaw, identified as CVE-2026-32590. This vulnerability resides in the handling of resumable container image layer uploads. Specifically, the way Quay stores intermediate data in its database during the upload process is susceptible to tampering. An attacker with the ability to manipulate this stored data can leverage this vulnerability to inject malicious serialized objects. When Quay attempts to deserialize this tampered data, it leads…
