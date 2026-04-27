---
title: OpenClaw Premature Cite Expansion Vulnerability (CVE-2026-35637)
slug: 2026-04-openclaw-auth-bypass
description: OpenClaw versions before 2026.3.22 are vulnerable to a timing issue where cite expansion occurs before channel and DM authorization checks, potentially allowing attackers to access or manipulate content before authorization.
date: "2026-04-09T22:16:32Z"
severities:
  - medium
tags:
  - vulnerability
  - authorization
  - timing-attack
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35637
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35637
  - https://github.com/openclaw/openclaw/commit/3cbf932413e41d1836cb91aed1541a28a3122f93
  - https://github.com/openclaw/openclaw/commit/630f1479c44f78484dfa21bb407cbe6f171dac87
  - https://github.com/openclaw/openclaw/commit/ebee4e2210e1f282a982c7ef2ad79d77a572fc87
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-vfg3-pqpq-93m4
  - https://www.vulncheck.com/advisories/openclaw-premature-cite-expansion-before-authorization-in-channel-and-dm
ioc_counts:
  email: 1
rules:
  - title: Detect Potential OpenClaw Cite Expansion Bypass
    description: Detects potential attempts to exploit the OpenClaw cite expansion vulnerability by monitoring for cite expansion events occurring before authorization checks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Content Modification After Cite Expansion
    description: Detects suspicious content modification events in OpenClaw after cite expansion, which might indicate exploitation of the authorization bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, in versions prior to 2026.3.22, suffers from a critical vulnerability related to the order of operations during cite expansion. Specifically, the application performs cite expansion before completing channel and Direct Message (DM) authorization checks. This timing issue allows attackers to potentially bypass authorization controls and interact with content that should otherwise be restricted. The vulnerability, identified as CVE-2026-35637, poses a risk of unauthorized access and…
