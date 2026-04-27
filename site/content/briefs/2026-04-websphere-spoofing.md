---
title: IBM WebSphere Liberty Identity Spoofing Vulnerability (CVE-2026-3621)
slug: 2026-04-websphere-spoofing
description: IBM WebSphere Application Server Liberty versions 17.0.0.3 through 26.0.0.4 are susceptible to identity spoofing when applications are deployed without proper authentication and authorization configurations, potentially leading to unauthorized access and privilege escalation.
date: "2026-04-23T00:18:31Z"
severities:
  - medium
tags:
  - cve-2026-3621
  - websphere
  - identity spoofing
  - cwe-269
vendors:
  - IBM
products:
  - WebSphere Application Server - Liberty
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-3621
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3621
  - https://www.ibm.com/support/pages/node/7270437
rules:
  - title: Detect WebSphere Liberty Unauthorized Access Attempt
    description: Detects attempts to access WebSphere Liberty applications without proper authentication headers, potentially indicating identity spoofing attempts related to CVE-2026-3621.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
  - title: WebSphere Liberty Unprotected Resource Access
    description: Detects access to sensitive resources on WebSphere Liberty without prior authentication, potentially indicating an attempt to exploit CVE-2026-3621.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-3621 identifies an identity spoofing vulnerability affecting IBM WebSphere Application Server Liberty versions 17.0.0.3 through 26.0.0.4. This vulnerability arises when applications are deployed on WebSphere Liberty without authentication or authorization mechanisms configured. An attacker could potentially exploit this flaw to impersonate legitimate users or services, gaining unauthorized access to resources and performing actions on their behalf. This vulnerability was reported to…
