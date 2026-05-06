---
title: VMware Aria Operations Vulnerabilities Allow Remote Code Execution and Privilege Escalation
slug: 2026-02-vmware-aria-rce
description: Multiple vulnerabilities in VMware Aria Operations, Cloud Foundation, and Telco Cloud Platform/Infrastructure could allow unauthenticated remote code execution (CVE-2026-22719) and privilege escalation (CVE-2026-22720, CVE-2026-22721).
date: "2026-02-25T15:21:35Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - vmware
  - aria-operations
  - rce
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://ccb.belgium.be/advisories/warning-severe-vulnerabilities-vmware-products-including-vmware-aria-operations-could-be
  - https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/36947
  - https://knowledge.broadcom.com/external/article/430349
rules:
  - title: Detect Connection to VMware Advisory URL
    description: Detects connections to the VMware security advisory URL, which may indicate research or reconnaissance activity related to the vulnerability.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1598
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to VMware Workaround URL
    description: Detects connections to the VMware KB article URL, which may indicate research or reconnaissance activity related to the workaround.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1598
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Broadcom released an advisory in February 2026 addressing three vulnerabilities in VMware Aria Operations, Cloud Foundation, Telco Cloud Platform, and Telco Cloud Infrastructure. CVE-2026-22719 (CVSS 8.1) is a command injection vulnerability in Aria Operations that can lead to RCE if exploited during a support-assisted product migration. CVE-2026-22720 (CVSS 8.0) is a cross-site scripting vulnerability where a malicious actor with privileges to create custom benchmarks may be able to inject…
