---
title: Multiple Vulnerabilities in Red Hat Ansible Automation Platform
slug: 2026-04-redhat-ansible-vulns
description: A remote, anonymous attacker can exploit multiple vulnerabilities in Red Hat Ansible Automation Platform to perform denial of service, execute arbitrary code, bypass security measures, manipulate data, disclose information, or conduct XSS attacks.
date: "2026-04-15T11:37:19Z"
severities:
  - critical
tags:
  - ansible
  - redhat
  - vulnerability
  - dos
  - xss
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0935
rules:
  - title: Detect Suspicious HTTP Request to Ansible Web Interface
    description: Detects suspicious HTTP requests potentially targeting vulnerabilities in the Ansible Automation Platform web interface.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Process Execution from Ansible User
    description: Detects suspicious process execution initiated by the Ansible user, potentially indicating a compromised platform.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Multiple vulnerabilities exist in Red Hat Ansible Automation Platform that could be exploited by a remote, anonymous attacker. The vulnerabilities span a wide range of potential impacts, including denial of service (DoS), arbitrary code execution, security bypass, data manipulation, information disclosure, and cross-site scripting (XSS). While the specific CVEs are not detailed, the broad range of potential exploits suggests a critical need for patching and mitigation. The lack of specific…
