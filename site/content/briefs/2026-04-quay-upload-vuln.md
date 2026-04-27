---
title: Red Hat Quay Image Upload Interference Vulnerability (CVE-2026-32589)
slug: 2026-04-quay-upload-vuln
description: CVE-2026-32589 describes a vulnerability in Red Hat Quay's container image upload process where an authenticated user can interfere with other users' uploads, potentially leading to unauthorized access and modification.
date: "2026-04-08T18:25:59Z"
severities:
  - medium
tags:
  - quay
  - image upload
  - vulnerability
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32589
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32589
  - https://access.redhat.com/security/cve/CVE-2026-32589
  - https://bugzilla.redhat.com/show_bug.cgi?id=2446963
rules:
  - title: Detect Quay Image Upload Interference Attempt
    description: Detects potential attempts to interfere with Red Hat Quay image uploads by monitoring API requests that could modify image metadata or cancel uploads.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect Quay Manifest Manipulation
    description: Detects attempts to manipulate container image manifests in Red Hat Quay, potentially indicating unauthorized modification.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-32589 identifies a flaw within the container image upload process of Red Hat Quay. An authenticated user, possessing push access to at least one repository within the Quay registry, can exploit this vulnerability to disrupt image uploads initiated by other users. The scope of this interference extends to uploads occurring in repositories where the attacker lacks explicit access privileges. This vulnerability allows a malicious actor to potentially read, modify, or even cancel another…
