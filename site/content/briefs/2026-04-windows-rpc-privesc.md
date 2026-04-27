---
title: CVE-2026-26183 Windows RPC API Local Privilege Escalation
slug: 2026-04-windows-rpc-privesc
description: CVE-2026-26183 allows a locally authenticated attacker to escalate privileges due to improper access control within the Windows RPC API.
date: "2026-04-14T18:26:47Z"
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - rpc
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26183
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26183
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26183
ioc_counts:
  email: 1
rules:
  - title: Detect Potential Exploitation of CVE-2026-26183 via Suspicious Process Creation
    description: Detects suspicious process creations by low-privileged users that might be related to the exploitation of CVE-2026-26183. This rule looks for unusual processes being spawned by standard users which could indicate privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Malicious RPC Client
    description: Detects potential malicious RPC client activity based on unusual process execution.  This is a heuristic and should be tuned for the environment.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-26183 is a vulnerability in the Windows RPC API that enables a local attacker with existing authorized access to elevate their privileges. This improper access control issue poses a significant risk as it allows a malicious actor to gain higher-level permissions on a compromised system. The vulnerability, reported on April 14, 2026, affects the Windows operating system. An attacker could potentially leverage this vulnerability to perform actions such as installing software, modifying…
