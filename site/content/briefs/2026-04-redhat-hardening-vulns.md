---
title: Multiple Vulnerabilities in Red Hat Hardened Images RPMs
slug: 2026-04-redhat-hardening-vulns
description: Remote, anonymous attackers can exploit vulnerabilities in Red Hat Hardened Images RPMs to bypass security measures, cause denial of service, disclose sensitive information, or potentially execute code.
date: "2026-04-21T08:44:11Z"
severities:
  - critical
tags:
  - redhat
  - vulnerability
  - denial-of-service
  - information-disclosure
  - code-execution
  - linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1183
rules:
  - title: Detect Vulnerable Red Hat Package Installation
    description: Detects the installation or upgrade of potentially vulnerable Red Hat packages (jq or pyOpenSSL).
    platform: sigma
    severity: medium
    tactics:
      - vulnerability
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Process Execution by Vulnerable RPM
    description: Detects suspicious process execution originating from processes associated with jq or pyOpenSSL.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Multiple vulnerabilities affect Red Hat Hardened Images RPMs. A remote, anonymous attacker could exploit these weaknesses to compromise the system. The vulnerabilities could lead to bypassing security precautions, causing a denial-of-service condition, disclosing sensitive information, or performing unspecified attacks, including potential code execution. The specifics of the vulnerable RPMs (jq and pyOpenSSL) are mentioned, highlighting a focus on common utilities. While the exact CVEs are not…
