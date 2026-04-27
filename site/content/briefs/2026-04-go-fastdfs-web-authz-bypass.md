---
title: perfree go-fastdfs-web Improper Authorization Vulnerability (CVE-2026-6105)
slug: 2026-04-go-fastdfs-web-authz-bypass
description: CVE-2026-6105 is a critical vulnerability in perfree go-fastdfs-web versions up to 1.3.7, allowing for remote improper authorization due to a flaw in the doInstall Interface, potentially leading to unauthorized system access and control.
date: "2026-04-11T22:16:01Z"
severities:
  - critical
tags:
  - CVE-2026-6105
  - Improper Authorization
  - go-fastdfs-web
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-6105
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6105
  - https://gitee.com/ying-xiujie/cve/issues/IGB6M9
  - https://vuldb.com/vuln/356964
rules:
  - title: Detect Suspicious doInstall Interface Access
    description: Detects suspicious access attempts to the doInstall interface in perfree go-fastdfs-web, indicative of CVE-2026-6105 exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Access to InstallController.java
    description: Detects unauthorized access attempts to InstallController.java, which may indicate an attempt to exploit CVE-2026-6105
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-6105, has been identified in perfree go-fastdfs-web, affecting versions up to 1.3.7. The vulnerability resides in the `src/main/java/com/perfree/controller/InstallController.java` file, specifically within the `doInstall` Interface component. This flaw allows for improper authorization, enabling remote attackers to potentially bypass security measures and gain unauthorized access. The exploit has been publicly disclosed, increasing the risk of…
