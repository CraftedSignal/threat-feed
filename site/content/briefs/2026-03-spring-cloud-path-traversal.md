---
title: Spring Cloud Config Server Path Traversal Vulnerability (CVE-2026-22739)
slug: 2026-03-spring-cloud-path-traversal
description: A path traversal vulnerability exists in Spring Cloud Config Server versions 3.1.x before 3.1.13, 4.1.x before 4.1.9, 4.2.x before 4.2.3, 4.3.x before 4.3.2, and 5.0.x before 5.0.2, allowing unauthenticated remote attackers to access files outside configured search directories when using the native file system backend.
date: "2026-03-24T01:17:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-22739
  - path-traversal
  - spring-cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22739
  - https://spring.io/security/cve-2026-22739
rules:
  - title: Detect Path Traversal in Spring Cloud Config Server Profile Parameter
    description: Detects path traversal attempts in requests to Spring Cloud Config Server by looking for '../' sequences in the profile parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Path Traversal in Spring Cloud Config Server URL
    description: Detects path traversal attempts in URL requests to Spring Cloud Config Server by looking for '../' sequences in the URL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-22739 describes a path traversal vulnerability affecting Spring Cloud Config Server. The vulnerability arises when the Config Server is configured with the native file system backend and processes a request containing a profile parameter. An attacker can manipulate this parameter to access files outside the intended search directories. This issue impacts Spring Cloud versions 3.1.x before 3.1.13, 4.1.x before 4.1.9, 4.2.x before 4.2.3, 4.3.x before 4.3.2, and 5.0.x before 5.0.2. This…
